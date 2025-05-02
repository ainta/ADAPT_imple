#!/bin/bash

# result file
> ADAPT_result.txt
> FROST_result.txt

# argv
argv=("20 10" "20 14" "20 20" "100 50" "100 70" "100 100" "500 250" "500 350" "500 500")

cd ADAPT
for args in "${argv[@]}"; do
	go run main.go $args >> ../ADAPT_result.txt
	echo -e "\n===========\n" >> ../ADAPT_result.txt
	echo "ADAPT $args is finished"
	sleep 1
done

cd ..

cd FROST
for args in "${argv[@]}"; do
	go run main.go $args >> ../FROST_result.txt
	echo -e "\n===========\n" >> ../FROST_result.txt
	echo "FROST $args is finished"
	sleep 1
done

cd ..
