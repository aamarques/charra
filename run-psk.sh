make -j
export LOG_LEVEL_CHARRA=DEBUG
export LOG_LEVEL_COAP=DEBUG 
#(bin/attester &); sleep .2 ; bin/verifier ; sleep 1 ; pkill -SIGINT -f bin/attester
#(bin/relying_party &); (bin/attester &); sleep .2 ; bin/verifier ; sleep 30 ; pkill -SIGINT -f bin/attester ; pkill -SIGINT -f bin/relying_party 
(bin/attester  -p &)
sleep .2 
bin/relying_party -p &
sleep .22 
bin/verifier -p
sleep .2
pkill -SIGINT -f bin/attester  
pkill -SIGINT -f bin/relying_party 
