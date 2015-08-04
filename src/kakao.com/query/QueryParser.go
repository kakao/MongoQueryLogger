package query


import (
	"fmt"
	"bytes"
	"strings"
	"time"
	"strconv"
	"encoding/binary"
	"encoding/hex"
	"hash/fnv"
	"sync/atomic"
//	"net"
//	"time"
//	"encoding/binary"
	
	"../../github.com/miekg/pcap"
	"../../bson"
)

const (
	OP_UPDATE = 2001 // update document
	OP_QUERY = 2004 // query a collection
	OP_DELETE = 2006 // Delete documents
	
	OP_GET_MORE = 2005 // Get more data from a query. See Cursors
	OP_INSERT = 2002 // insert new document
	
	OP_REPLY = 1 // Reply to a client request. responseTo is set
	OP_MSG = 1000 // generic msg command followed by a string
	// RESERVED = 2003 // formerly used for OP_GET_BY_OID
	OP_KILL_CURSORS = 2007 // Tell database client is done with a cursor
)

/** MongoDB wire protocol

struct MsgHeader {
    int32   messageLength; // total message size, including this
    int32   requestID;     // identifier for this message
    int32   responseTo;    // requestID from the original request
                           //   (used in reponses from db)
    int32   opCode;        // request type - see table below
}

struct OP_QUERY {
    MsgHeader header;                 // standard message header
    int32     flags;                  // bit vector of query options.  See below for details.
    cstring   fullCollectionName ;    // "dbname.collectionname"
    int32     numberToSkip;           // number of documents to skip
    int32     numberToReturn;         // number of documents to return
                                      //  in the first OP_REPLY batch
    document  query;                  // query object.  See below for details.
                                      // BSON document that represents the query. The query will contain one or more elements, all of which must match for a document to be included in the result set. Possible elements include $query, $orderby, $hint, $explain, and $snapshot.
  [ document  returnFieldsSelector; ] // Optional. Selector indicating the fields
                                      //  to return.  See below for details.
}

struct OP_DELETE {
    MsgHeader header;             // standard message header
    int32     ZERO;               // 0 - reserved for future use
    cstring   fullCollectionName; // "dbname.collectionname"
    int32     flags;              // bit vector - see below for details.
    document  selector;           // query object.  See below for details.
                                  // BSON document that represent the query used to select the documents to be removed. The selector will contain one or more elements, all of which must match for a document to be removed from the collection.
}

struct OP_UPDATE {
    MsgHeader header;             // standard message header
    int32     ZERO;               // 0 - reserved for future use
    cstring   fullCollectionName; // "dbname.collectionname"
    int32     flags;              // bit vector. see below
    document  selector;           // the query to select the document
                                  // BSON document that specifies the query for selection of the document to update.
    document  update;             // specification of the update to perform
}
*/

type UserRequest struct {
	Packet       *pcap.TcpPacket
	
	messageLength int32 // total message size, including this
	requestId     int32 // identifier for this message
	responseTo    int32 // requestID from the original request (used in reponses from db)
	opCode        int32 // request type - see table below
	
	//isSystemObject     bool   // Whether this collection is system object or user object
	//fullCollectionName string // full namespace of collection
	//Query         string // query of OP_QUERY or select of OP_DELETE and OP_UPDATE
}

// Map element for Execution counter
type ExecCounter struct {
	Query        string
	Counter      uint64
}

var threadStartTime time.Time

func (cnt *ExecCounter) increment(inc uint64){
	atomic.AddUint64(&cnt.Counter, inc)
}

func isSystemCollection(name string) (bool){
	if strings.HasPrefix(name, "system.") ||
		strings.HasPrefix(name, "admin.") ||
		strings.HasPrefix(name, "local.") ||
		strings.HasPrefix(name, "config.") {
			return true
	}

	return false 
}

func ParseQuery(workerIdx int, queue chan *UserRequest, queryCounterMap map[uint64]*ExecCounter, parseUpdateSetter bool, maxUniqueQueryCount int, validPacketCaptured *uint64, errorPacketCounter *uint64, systemQueryCounter *uint64, userQueryCounter *uint64) (){
	threadStartTime = time.Now()
	for{
		req := <-queue // read from a channel
		if req.parse(queryCounterMap, parseUpdateSetter, maxUniqueQueryCount, systemQueryCounter, userQueryCounter) {
			*validPacketCaptured++
		}else{
			*errorPacketCounter++
		}
	}
}

func (req *UserRequest) parse(queryCounterMap map[uint64]*ExecCounter, parseUpdateSetter bool, maxUniqueQueryCounter int, systemQueryCounter *uint64, userQueryCounter *uint64) (bool){
	var fullCollectionName string
	var foundNullTerminator bool = false
	var currPosition int32 = 0
	
	req.Packet.Parse()
	if req.Packet.IsValidTcpPacket && req.Packet.Payload!=nil && len(req.Packet.Payload)>0 { // pkt.Paylod is mongodb request data
		payload := req.Packet.Payload
		if(payload!=nil && len(payload)>=16){
			reader := bytes.NewReader(payload)
			err := binary.Read(reader, binary.LittleEndian, &req.messageLength)
			if err != nil {
				fmt.Println("binary.Read for header.messagLength failed:", err)
				return false
			}
			
			if int(req.messageLength)>len(payload) {
				return false
			}
	
			err = binary.Read(reader, binary.LittleEndian, &req.requestId)
			if err != nil {
				fmt.Println("binary.Read for header.requestId failed:", err)
				return false
			}
			
			err = binary.Read(reader, binary.LittleEndian, &req.responseTo)
			if err != nil {
				fmt.Println("binary.Read for header.responseTo failed:", err)
				return false
			}
			
			err = binary.Read(reader, binary.LittleEndian, &req.opCode)
			if err != nil {
				fmt.Println("binary.Read for header.opCode failed:", err)
				return false
			}
			
			if !(req.opCode==OP_QUERY || req.opCode==OP_GET_MORE ||
					req.opCode==OP_INSERT || req.opCode==OP_UPDATE || req.opCode==OP_DELETE) { // Except this just ignore
				return true
			}

			// read collection name, collection name start from 20th byte for all packet ( op_query, op_delete, op_update )
			for currPosition=20; currPosition<req.messageLength; currPosition++ {
				if payload[currPosition]==0x00 {
					// stop here
					fullCollectionName = string(payload[20:currPosition])
					foundNullTerminator = true
					break
				}
			}
			currPosition++ // Increment for Null terminator (0x00)
			
			if foundNullTerminator==false {
				fmt.Println("Null terminator not found in packet during parse full collection name")
				return false
			}
			
			// Just skip for system collection
			if isSystemCollection(fullCollectionName) {
				*systemQueryCounter++
				return true
			}
			*userQueryCounter++
			
			// From here, real query parsing and accumulate query pattern only for op_query || op_update || op_delete
			if req.opCode==OP_QUERY {
				currPosition += (4/*skip*/+4/*limit*/)
			}else if req.opCode==OP_UPDATE || req.opCode==OP_DELETE { // op_update and op_delete ( and op_get_more)
				currPosition += 4/*flag*/
			}else{
				return true // Skip anything else
			}
	
			// Total length of first document (if opCode==OP_UPDATE, this is selector document length
			firstDocLen := int32(uint32(payload[currPosition]) | uint32(payload[currPosition+1])<<8 | uint32(payload[currPosition+2])<<16 | uint32(payload[currPosition+3])<<24)

			var queryDoc bson.D
			var updateDoc bson.D

			// 1. Parse Query Condition
			err = bson.Unmarshal(payload[currPosition:], &queryDoc)
			if err!=nil {
				fmt.Println("Query parsing failed : ", err)
				fmt.Println(hex.Dump(req.Packet.Payload))
				return false;
			}

			var buffer bytes.Buffer
			buffer.WriteString(fullCollectionName)
			buffer.WriteString(":")
			buffer.WriteString(req.getOperation())
			buffer.WriteString(Stringify(queryDoc))

			// 2. Parse Update Setter (if needed)
			if req.opCode==OP_UPDATE && parseUpdateSetter {
				// Total length of second document (if opCode==OP_UPDATE, this is update(setter) document length
				secondDocLen := int32(uint32(payload[currPosition+firstDocLen]) | uint32(payload[currPosition+firstDocLen+1])<<8 |
								uint32(payload[currPosition+firstDocLen+2])<<16 | uint32(payload[currPosition+firstDocLen+3])<<24)
				if (currPosition + firstDocLen + secondDocLen)<=int32(len(payload)) {
					err = bson.Unmarshal(payload[(currPosition+firstDocLen):], &updateDoc)
					if err!=nil {
						fmt.Println("Query (update setter) parsing failed : ", err)
						fmt.Println(hex.Dump(req.Packet.Payload))
						return false;
					}

					buffer.WriteString(", SETTER:")
					buffer.WriteString(Stringify(updateDoc))
				}
			}

			reqString := buffer.String()
			
			// for Debugging
			// fmt.Println(">> Request : ",reqString)
			
			// Accumulate query execution counter
			h := fnv.New64a()
			h.Write([]byte(reqString))
			hash := h.Sum64()
			counter := queryCounterMap[hash]
			if(counter==nil){
				if len(queryCounterMap) > maxUniqueQueryCounter {
					// fmt.Println(">> Max distinct query counter is ",maxUniqueQueryCounter, ", Increase max_unique_query parameter to continue... ")
					
					endTimeStr := time.Now().String()
					startTimeStr := threadStartTime.String()
					fmt.Println("-- Query map ----------------------------------------------------------")
					fmt.Println("--",startTimeStr[0:19]," ~ ",endTimeStr[0:19])
					fmt.Println("-----------------------------------------------------------------------")
					for _, v := range queryCounterMap {
						fmt.Println(v.Counter, v.Query)
					}
					fmt.Println("-----------------------------------------------------------------------")
					
					var buffer bytes.Buffer
					buffer.WriteString(">> Max distinct query counter is ")
					buffer.WriteString(strconv.Itoa(maxUniqueQueryCounter))
					buffer.WriteString(", Increase max_unique_query parameter to continue... ")
					panic(buffer.String())
				}
				queryCounterMap[hash] = &ExecCounter{
					Query: reqString,
					Counter: uint64(1),
				}
			}else{
				counter.increment(1)
			}
			
			return true
		}
	}
	
	return false
}


func (req *UserRequest) getOperation() (string){
	if req.opCode==OP_QUERY {
		return "OP_QUERY"
	}else if req.opCode==OP_GET_MORE {
		return "OP_GET_MORE"
	}else if req.opCode==OP_UPDATE {
		return "OP_UPDATE"
	}else if req.opCode==OP_DELETE {
		return "OP_DELETE"
	}else if req.opCode==OP_INSERT {
		return "OP_INSERT"
	}else if req.opCode==OP_REPLY {
		return "OP_REPLY"
	}else if req.opCode==OP_KILL_CURSORS {
		return "OP_KILL_CURSORS"
	}else if req.opCode==OP_MSG {
		return "OP_MSG"
	}
	
	return "OP_UNKNOWN"
}