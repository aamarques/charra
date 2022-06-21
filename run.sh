make -j
#export LOG_LEVEL_CHARRA=TRACE
#export LOG_LEVEL_COAP=DEBUG 
#(bin/attester &); sleep .2 ; bin/verifier ; sleep 1 ; pkill -SIGINT -f bin/attester
#(bin/relying_party &); (bin/attester &); sleep .2 ; bin/verifier ; sleep 30 ; pkill -SIGINT -f bin/attester ; pkill -SIGINT -f bin/relying_party 
(bin/attester &)
sleep .2 
bin/relying_party &
sleep .2 
bin/verifier 
sleep 1 
#bin/relying_party &
sleep 1 
pkill -SIGINT -f bin/attester  
pkill -SIGINT -f bin/relying_party 
