make -j
export  LOG_LEVEL_CHARRA=TRACE 
export LOG_LEVEL_COAP=DEBUG 
(bin/attester &); sleep .2 ; bin/verifier ; sleep 1 ; pkill -SIGINT -f bin/attester
