package main

import (
	"fmt"
	"os"
	"strconv"
	"time"

	frost "ADAPT_FROST/FROST/algorithm"
)

// 명령행 플래그
// go run main.go [n] [t] - 기본 FROST 실행
// go run main.go weight-test - 가중치 테스트 실행

func main() {
	// 명령행 인수 확인
	if len(os.Args) > 1 {
		// 가중치 테스트 모드
		if os.Args[1] == "weight-test" {
			fmt.Println("가상화된 가중치 테스트 실행 중...")
			frost.TestVirtualizedWeights()
			return
		}

		// 기본 FROST 실행 모드
		n, _ := strconv.Atoi(os.Args[1])
		t := n
		if len(os.Args) > 2 {
			t, _ = strconv.Atoi(os.Args[2])
		}

		fmt.Printf("FROST 실행 중 (참여자: %d, 임계값: %d)\n", n, t)

		start := time.Now()
		frost.Round1()
		end := time.Since(start)
		fmt.Println("Round 1 실행 시간: ", end)
		fmt.Println()

		time.Sleep(time.Millisecond)

		start = time.Now()
		frost.Round2()
		end = time.Since(start)
		fmt.Println("Round 2 실행 시간: ", end)
		fmt.Println()

		time.Sleep(time.Millisecond)

		start = time.Now()
		frost.Preprocessing()
		end = time.Since(start)
		fmt.Println("전처리 실행 시간: ", end)
		fmt.Println()

		time.Sleep(time.Millisecond)

		start = time.Now()
		frost.Sign()
		end = time.Since(start)
		fmt.Println("서명 실행 시간: ", end)
		fmt.Println()

		time.Sleep(time.Millisecond)

		start = time.Now()
		frost.Verify()
		end = time.Since(start)
		fmt.Println("검증 실행 시간: ", end)
		fmt.Println()

		return
	}

	// 매개변수 없이 실행 시 사용법 안내
	fmt.Println("사용법:")
	fmt.Println("  go run main.go [n] [t] - 기본 FROST 실행")
	fmt.Println("  go run main.go weight-test - 가중치 테스트 실행")
}
