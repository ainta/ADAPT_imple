package main

import (
	. "ADAPT_FROST/ADAPT/algorithm"
	"fmt"
	"time"
)

func main() {

	start := time.Now()
	Round1()
	end := time.Since(start)
	fmt.Println("time for round 1 : ", end)
	fmt.Println()

	time.Sleep(time.Millisecond)

	start = time.Now()
	Round2()
	end = time.Since(start)
	fmt.Println("time for round 2 : ", end)
	fmt.Println()

	time.Sleep(time.Millisecond)

	start = time.Now()
	Preprocessing()
	end = time.Since(start)
	fmt.Println("time for preprocessing : ", end)
	fmt.Println()

	time.Sleep(time.Millisecond)

	start = time.Now()
	Sign()
	end = time.Since(start)
	fmt.Println("time for signing : ", end)
	fmt.Println()

	time.Sleep(time.Millisecond)

	start = time.Now()
	Verify()
	end = time.Since(start)
	fmt.Println("time for verifying : ", end)
	fmt.Println()

	time.Sleep(time.Millisecond)

	start = time.Now()
	Adapt_WIncrease()
	end = time.Since(start)
	fmt.Println("time for adapt WIncrease : ", end)
	fmt.Println()

	time.Sleep(time.Millisecond)

	start = time.Now()
	Adapt_TIncrease()
	end = time.Since(start)
	fmt.Println("time for adapt TIncrease : ", end)
	fmt.Println()

	time.Sleep(time.Millisecond)

	start = time.Now()
	Adapt_WDecrease()
	end = time.Since(start)
	fmt.Println("time for adapt WDecrease : ", end)
	fmt.Println()

	time.Sleep(time.Millisecond)

	start = time.Now()
	Adapt_TDecrease()
	end = time.Since(start)
	fmt.Println("time for adapt TDecrease : ", end)
	fmt.Println()
}
