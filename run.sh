#!/bin/bash

./src/MongoQueryLogger \
  --interface="eth0" \
  --port=27017 \
  --snapshot_len=8192 \
  --read_timeout=100 \
  --queue_size=100 \
  --thread_count=5 \
  --max_mem_mb=64 \
  --max_unique_query=500 \
  --parse_update_setter=false