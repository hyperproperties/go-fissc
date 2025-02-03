package main

import "fmt"

func main() {
	for ptc > 0 {
		fmt.Printf("Enter your %d-digit PIN (digits separated by space):", PINSize)
		for i := 0; i < PINSize; i++ {
			fmt.Scan(&userPIN[i])
		}

		authenticated := VerifyPIN()

		if authenticated {
			fmt.Println("Authentication successful!")
		} else {
			fmt.Println("Incorrect PIN. Remaining attempts:", ptc)
		}

		if OracleAuth(authenticated) {
			panic("OracleAuth violated")
		}

		if OraclePTC() {
			panic("OraclePTC violated")
		}
	}

	fmt.Println("No more remaining attempts")
}
