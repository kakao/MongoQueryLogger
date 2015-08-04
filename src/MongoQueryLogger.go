package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"
	"strings"
	"runtime"
	"strconv"
	"io/ioutil"
//	"encoding/binary"
//	"encoding/hex"
//	"hash/adler32"
	
	"./github.com/miekg/pcap"
	"./kakao.com/query"
)

const (
	TYPE_IP  = 0x0800
	TYPE_ARP = 0x0806
	TYPE_IP6 = 0x86DD

	IP_ICMP = 1
	IP_INIP = 4
	IP_TCP  = 6
	IP_UDP  = 17
)

var (
	// Packet capture
	device  	= flag.String("interface", "", "Network interface to capture packet (example : eth0, lo")
	port    	= flag.Int("port", 27017, "Network port to capture packet (This is the listening port of MongoDB server")
	threads    	= flag.Int("thread_count", 4, "Message queue publisher counter")
	max_queue 	= flag.Int("queue_size", 100, "Internal queue length of each publisher thread")
	
	snaplen 	= flag.Int("snapshot_len", 8192, "Snapshot length of packet capture")   // Default 8KB
	read_timeout= flag.Int("read_timeout", 100, "Read timeout of packet capture in milli-second") // Milli-second

	max_unique_query = flag.Int("max_unique_query", 10000, "How many distinct query we can accumulate, if counter of distnct query over flow this then stop the processing")
	parse_update_setter = flag.Bool("parse_update_setter", false, "Parse and collect setter document of op_update packet") 
	max_mem_mb     = flag.Int("max_mem_mb", 64, "How much memory collector use at maximum (this is for resident memory size)")
	
	help    	= flag.Bool("help", false, "Print this message")
)

// Print status interval second
//*TEMPORAL* const STATUS_INTERVAL_SECOND = uint64(10)
const STATUS_INTERVAL_SECOND = uint64(1)

// Internal queue for rabbit mq publisher
var queues []chan *query.UserRequest

/**
 * Global status variables
 */
var totalPacketCaptured   uint64
var validPacketCaptureds  []uint64
var errorPacketCounters   []uint64
var overflowPacketCounter uint64
var systemQueryCounters   []uint64
var userQueryCounters     []uint64


var startTime time.Time

/**
 * Packet
 *
 * + TCPDUMP man page : http://linux.die.net/man/8/tcpdump
 * + TCP Flags (http://en.wikipedia.org/wiki/Transmission_Control_Protocol)
 *       SYN - Initiates a connection
 *       ACK - Acknowledges received data
 *       FIN - Closes a connection
 *       RST - Aborts a connection in response to an error
 *       RST - Reset the connection
 *       NS  – ECN-nonce concealment protection (experimental: see RFC 3540).
 *       CWR – Congestion Window Reduced (CWR) flag is set by the sending host to indicate that it received a TCP segment with the ECE flag set and had responded in congestion control mechanism (added to header by RFC 3168).
 *       ECE – ECN-Echo has a dual role, depending on the value of the SYN flag. It indicates:
 *             If the SYN flag is set (1), that the TCP peer is ECN capable.
 *             If the SYN flag is clear (0), that a packet with Congestion Experienced flag in IP header set is received during normal transmission (added to header by RFC 3168).
 *       PSH - (Push), The sending application informs TCP that data should be sent immediately. (Do not waiting for full buffer)
 *             http://packetlife.net/blog/2011/mar/2/tcp-flags-psh-and-urg/
 *       URG - The URG flag is used to inform a receiving station that certain data within a segment is urgent and should be prioritized. If the URG flag is set, the receiving station evaluates the urgent pointer, a 16-bit field in the TCP header. This pointer indicates how much of the data in the segment, counting from the first byte, is urgent.
 *             http://packetlife.net/blog/2011/mar/2/tcp-flags-psh-and-urg/
 *
 *
 * + Snapshot-length (So, snapshot-length must be greater than 64 byte length
 *   - Size of Ethernet frame - 24 Bytes
 *   - Size of IPv4 Header (without any options) - 20 bytes
 *   - Size of TCP Header (without any options) - 20 Bytes
 *   - So total size of empty TCP datagram - 24 + 20 + 20 = 64 bytes
 *   
 *   - Size of UDP header - 8 bytes
 *   - So total size of empty UDP datagram - 24 + 20 + 8 = 52 bytes
 */
func main() {
	runtime.GOMAXPROCS(6)
	// This limitation make "out of memory"
	// MRTECollector need about 1GB maximum (But usually RES size is 15MB)
	// limitMemory(32*1024*1024/*Rlimit.Cur*/, 256*1024*1024/*Rlimit.Max*/)
	
	flag.Parse()
	if device==nil || *device=="" ||
		*help {	
		flag.Usage()
		os.Exit(0)
	}

	expr := fmt.Sprintf("tcp dst port %d", *port)
	
	// Prepare rabbit mq publisher
	var realQueueSize = 100
	var realThreadCount int = 4
	if *threads>=2 && *threads<=10 {
		realThreadCount = *threads
	}
	if *max_queue>=100 && *max_queue<=5000 {
		realQueueSize = *max_queue
	}
	
	// Query map 
	//     int64 - hash of query
	var queryCounterMap map[uint64]*query.ExecCounter
	queryCounterMap = make(map[uint64]*query.ExecCounter)
	
	validPacketCaptureds = make([]uint64, realThreadCount)
	errorPacketCounters = make([]uint64, realThreadCount)
	systemQueryCounters = make([]uint64, realThreadCount)
	userQueryCounters = make([]uint64, realThreadCount)
	for idx:=0; idx<realThreadCount; idx++ {
		workerIdx := idx
		queue := make(chan *query.UserRequest, realQueueSize)
		queues = append(queues, queue)
		
		// Run sub-thread(goroutine) for publishing message
		go query.ParseQuery(workerIdx, queue, queryCounterMap, *parse_update_setter, *max_unique_query, &validPacketCaptureds[idx], &errorPacketCounters[idx], &systemQueryCounters[idx], &userQueryCounters[idx])
	}

	// Prepare packet capturer
	h, err := pcap.OpenLive(*device, int32(*snaplen), true, int32(*read_timeout))
	if h == nil {
		fmt.Println(os.Stderr, "[FATAL] MRTECollector : Failed to open packet capture channel : ", err)
		return
	}
	defer h.Close()
	
	err = h.SetDirection("in")
	if err != nil {
		fmt.Println("[FATAL] MRTECollector : SetDirection failed, ", err)
		return
	}

	if expr != "" {
		fmt.Println("[INFO]  MRTECollector : Setting capture filter to '", expr, "'")
		ferr := h.SetFilter(expr)
		if ferr != nil {
			fmt.Println("[ERROR] MRTECollector : Failed to set packet capture filter : ", ferr)
		}
	}
	
	// Add signal handler for KILL | SIGUSR1 | SIGUSR2
	addSignalHandler(h, queryCounterMap)






	
	
	
	go func(){
		fmt.Println("[INFO]  Skip sending init database information")
		
		// Print processing informations
		loopCounter := 0
		packetDropped := uint64(0)
		overflowPacketCounter := uint64(0)
		
		// Previous term status variable
		cTotalPacketCaptured := uint64(0)
		pTotalPacketCaptured := uint64(0)
		pValidPacketCounter := uint64(0)
		pPacketDropped := uint64(0)
		pOverflowPacketCounter := uint64(0)
		pErrorPacketCounter := uint64(0)
		pSystemQueryCounter := uint64(0)
		pUserQueryCounter := uint64(0)
		
		validPacketCounter := uint64(0)
		errorPacketCounter := uint64(0)
		waitingQueueCounter := uint64(0)
		systemQueryCounter := uint64(0)
		userQueryCounter := uint64(0)

		// idleSecondSinceLastPurgeGarbageConnection := 0
		for {
			startTime := time.Now()
			if loopCounter % 20 == 0 {
				fmt.Println()
				fmt.Printf("DateTime               TotalPacket   ValidPacket   PacketDropped    overflowPacket   SystemQuery     UserQuery   WaitingQueueCnt   QueryPatternCnt   Ignore_or_Error\n")
				loopCounter = 0
			}
			
			pcapStats, err := h.Getstats()
			if err==nil {
				packetDropped = uint64(pcapStats.PacketsDropped)
				// packetIfDropped = uint64(pcapStats.PacketsIfDropped)
			}
			
			
			// Length of buffered waiting job of queue
			waitingQueueCounter = 0
			validPacketCounter = 0
			errorPacketCounter = 0
			systemQueryCounter = 0
			userQueryCounter = 0
			for idx:=0; idx<realThreadCount; idx++ {
				waitingQueueCounter += uint64(len(queues[idx]))
				validPacketCounter += validPacketCaptureds[idx]
				errorPacketCounter += errorPacketCounters[idx]
				systemQueryCounter += systemQueryCounters[idx]
				userQueryCounter += userQueryCounters[idx]
			}
			
			dt := time.Now().String()
			cTotalPacketCaptured = totalPacketCaptured

			fmt.Printf("%s  %13d %13d   %13d     %13d %13d %13d     %13d     %13d     %13d\n", dt[0:19], 
				uint64((cTotalPacketCaptured - pTotalPacketCaptured) / STATUS_INTERVAL_SECOND),
                uint64((validPacketCounter - pValidPacketCounter) / STATUS_INTERVAL_SECOND),
                uint64((packetDropped - pPacketDropped) / STATUS_INTERVAL_SECOND),
                uint64((overflowPacketCounter - pOverflowPacketCounter) / STATUS_INTERVAL_SECOND),
                uint64((systemQueryCounter - pSystemQueryCounter) / STATUS_INTERVAL_SECOND),
                uint64((userQueryCounter - pUserQueryCounter) / STATUS_INTERVAL_SECOND),
                waitingQueueCounter,
                len(queryCounterMap),
                uint64((errorPacketCounter - pErrorPacketCounter) / STATUS_INTERVAL_SECOND))
			// Check memory usage before sleep
			checkMemoryUsage(int64(*max_mem_mb) * 1024 * 1024)

			elapsedNanoSeconds := time.Since(startTime)
			
			// Sleep
			// We have to calculate sleep-time with (10_second - above_processing_time)
			time.Sleep(time.Second * time.Duration(STATUS_INTERVAL_SECOND) - elapsedNanoSeconds) // each 10 seconds,
			loopCounter++
			
			pTotalPacketCaptured = cTotalPacketCaptured
			pValidPacketCounter = validPacketCounter
			pPacketDropped = packetDropped
			pOverflowPacketCounter = overflowPacketCounter
			pErrorPacketCounter = errorPacketCounter
			pSystemQueryCounter = systemQueryCounter;
			pUserQueryCounter = userQueryCounter;
		}
	}()
	
	
	// --------------------------------------------------------------------
	// Run packet capturer
	// --------------------------------------------------------------------
	startTime = time.Now()
	currentWorkerId := int(0)
	for pkt, r := h.NextEx(); r >= 0; pkt, r = h.NextEx() {
		if r==0 || pkt==nil {
			// This is packet capture timeout. just retry
			continue
		}
		
		totalPacketCaptured++
		
		if pkt.Len>(1024*5) { // If packet is greater than 5k, just drop it.
			overflowPacketCounter++
			continue
		}
	
		if currentWorkerId >= realThreadCount {
			currentWorkerId = 0
		}
		
		if len(queues[currentWorkerId]) > (realQueueSize-10) {
			panic("[FATAL] " + strconv.Itoa(currentWorkerId) + "th internal queue is fulled, required greater internal queue length")
		}
		
		queues[currentWorkerId] <- &query.UserRequest{
				Packet: pkt,
			}
		
		currentWorkerId++
	}
	fmt.Fprintln(os.Stderr, "[INFO] MRTECollector : ", h.Geterror())
}

const (
	statm_size = iota
	statm_resident
	statm_share
	statm_text
	statm_lib
	statm_data
	statm_dt /* over 2.6 */
	STATM_FIELD_END
)

func checkMemoryUsage(limit int64)(){
	var residentMemory int64
	var procStatContents string
	pageSize := int64(syscall.Getpagesize())
	if b, e := ioutil.ReadFile("/proc/self/statm"); e == nil {
		procStatContents = string(b)
	}
	
	fields := strings.Fields(procStatContents)
	if len(fields) >= (STATM_FIELD_END-1) {
		if stat_value, e := strconv.ParseInt(fields[statm_resident], 10, 64); e == nil {
			residentMemory = stat_value * pageSize
		}
	}
	
	if(residentMemory > limit){
		printAgentMemoryStats();
		panic("Memory usage is too high ("+strconv.FormatInt(residentMemory,10)+" > "+strconv.FormatInt(limit,10)+"), Increase memory limit or need to decrease memory usage")
	}
}

func printAgentMemoryStats(){
	// Get agent garbage collection status
	memoryStats := new(runtime.MemStats)
	runtime.ReadMemStats(memoryStats)

	// Print memory status to log file
	fmt.Printf("General statistics.\n")
	fmt.Printf("    Alloc      : %v // bytes allocated and still in use\n", memoryStats.Alloc)
	fmt.Printf("    TotalAlloc : %v // bytes allocated (even if freed)\n", memoryStats.TotalAlloc)
	fmt.Printf("    Sys        : %v // bytes obtained from system (sum of XxxSys below)\n", memoryStats.Sys)
	fmt.Printf("    Lookups    : %v // number of pointer lookups\n", memoryStats.Lookups)
	fmt.Printf("    Mallocs    : %v // number of mallocs\n", memoryStats.Mallocs)
	fmt.Printf("    Frees      : %v // number of frees\n", memoryStats.Frees)
	fmt.Printf("    \n")
	fmt.Printf("Main allocation heap statistics.\n")
	fmt.Printf("    HeapAlloc    : %v // bytes allocated and still in use\n", memoryStats.HeapAlloc)
	fmt.Printf("    HeapSys      : %v // bytes obtained from system\n", memoryStats.HeapSys)
	fmt.Printf("    HeapIdle     : %v // bytes in idle spans\n", memoryStats.HeapIdle)
	fmt.Printf("    HeapInuse    : %v // bytes in non-idle span\n", memoryStats.HeapInuse)
	fmt.Printf("    HeapReleased : %v // bytes released to the OS\n", memoryStats.HeapReleased)
	fmt.Printf("    HeapObjects  : %v // total number of allocated objects\n", memoryStats.HeapObjects)
	fmt.Printf("    \n")
	fmt.Printf("Low-level fixed-size structure allocator statistics.\n")
	fmt.Printf("  Inuse is bytes used now.\n")
	fmt.Printf("  Sys is bytes obtained from system.\n")
	fmt.Printf("    StackInuse  : %v // bytes used by stack allocator\n", memoryStats.StackInuse)
	fmt.Printf("    StackSys    : %v\n", memoryStats.StackSys)
	fmt.Printf("    MSpanInuse  : %v // mspan structures\n", memoryStats.MSpanInuse)
	fmt.Printf("    MSpanSys    : %v\n", memoryStats.MSpanSys)
	fmt.Printf("    MCacheInuse : %v // mcache structures\n", memoryStats.MCacheInuse)
	fmt.Printf("    MCacheSys   : %v\n", memoryStats.MCacheSys)
	fmt.Printf("    BuckHashSys : %v // profiling bucket hash table\n", memoryStats.BuckHashSys)
	fmt.Printf("    GCSys       : %v // GC metadata\n", memoryStats.GCSys)
	fmt.Printf("    OtherSys    : %v // other system allocations\n", memoryStats.OtherSys)
	fmt.Printf("    \n")
	fmt.Printf("Garbage collector statistics.\n")
	fmt.Printf("    NextGC       : %v // next collection will happen when HeapAlloc ≥ this amount\n", memoryStats.NextGC)
	fmt.Printf("    LastGC       : %v // end time of last collection (nanoseconds since 1970)\n", memoryStats.LastGC)
	fmt.Printf("    PauseTotalNs : %v\n", memoryStats.PauseTotalNs)
	fmt.Printf("    NumGC        : %v\n", memoryStats.NumGC)
	fmt.Printf("    EnableGC     : %v\n", memoryStats.EnableGC)
	fmt.Printf("    DebugGC      : %v\n", memoryStats.DebugGC)
}

func limitMemory(cur uint64, max uint64) {
	var rLimit syscall.Rlimit
	err := syscall.Getrlimit(syscall.RLIMIT_AS, &rLimit)
	if err != nil {
		fmt.Println("[ERROR] Failed to get resource limit : ", err)
	}
	// ftm.Println(rLimit)
	
	rLimit.Max = max // 1024 * 1024 * 256		// 256MB
	rLimit.Cur = cur // 1024 * 1024 * 64		//  64MB
	err = syscall.Setrlimit(syscall.RLIMIT_AS, &rLimit)
	if err != nil {
		fmt.Println("[ERROR] Failed to set resource limit : ", err)
	}
	err = syscall.Getrlimit(syscall.RLIMIT_AS, &rLimit)
	if err != nil {
		fmt.Println("[ERROR] Failed to get resource limit(2) : ", err)
	}
	fmt.Println("[INFO]  Memory usage limited to : ", rLimit)
}

func addSignalHandler(h *pcap.Pcap, queryCounterMap map[uint64]*query.ExecCounter) {
    signalChannel := make(chan os.Signal, 2)
	signal.Notify(signalChannel, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT, syscall.SIGABRT, syscall.SIGUSR1, syscall.SIGUSR2)
	go func() {
		for{
			sig := <-signalChannel
			
			endTimeStr := time.Now().String()
			startTimeStr := startTime.String()
			fmt.Println("-- Query map ----------------------------------------------------------")
			fmt.Println("--",startTimeStr[0:19]," ~ ",endTimeStr[0:19])
			fmt.Println("-----------------------------------------------------------------------")
			
//			if len(queryCounterMap)<=500 { // Sort and print it
//				var keys []int
//				keys = make([]int, len(queryCounterMap))
//				for key := range queryCounterMap {
//					keys = append(keys, key)
//				}
//				
//				sort.Ints(keys)
//    			for _, key := range keys {
//			    	v := queryCounterMap[key]
//			    	fmt.Println(v.Counter, v.Query)
//			    }
//			}else{ // Just print it without sort
				for _, v := range queryCounterMap {
					fmt.Println(v.Counter, v.Query)
				}
//			}
			
			fmt.Println("-----------------------------------------------------------------------")
			
			if sig == syscall.SIGUSR1 || sig ==syscall.SIGUSR2 {
				// Do nothing
			}else{
				fmt.Fprintln(os.Stderr, "[INFO] MRTECollector : Received signal : ", sig)
				h.Close()
				os.Exit(0)
			}
		}
	}()
}