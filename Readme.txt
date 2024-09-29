to run the program first use scanner program
compile it as so:
g++ scanner.cpp -o scanner
and then run scanner:
./scanner
then use compile and run the puzzlesolver file as so where (porti) are the ports returned form scanner:
g++ puzzlesolver.cpp -o puzzlesolver
./puzzlesolver <ip> <port1> <port2> <port3> <port4>
