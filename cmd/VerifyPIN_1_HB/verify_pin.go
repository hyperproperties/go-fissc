package main

import . "github.com/hyperproperties/fissc-go/pkg"

// The required pin size from the user and the length of the pin used by the card.
//
// The #define directive "PIN_SIZE" which is "4".
const PINSize = 4

// The allowed number of attempts before user is locked-out.
const MaxAttempts = 3

// The pin try counter (or ptc). This variable describes
// how many times one can attempt the verificaiton of a pin.
// It is reset to MaxAttempts when a correct pin has been entered.
//
// The global variable "extern SBYTE g_ptc".
var ptc int8 = MaxAttempts

// The card pin the user must match inorder to be authenticated.
//
// The global variable "extern UBYTE g_cardPin[PIN_SIZE]".
var cardPIN [PINSize]byte

// The user entered pin.
//
// The global variable "extern UBYTE g_userPin[PIN_SIZE]".
var userPIN [PINSize]byte

// A flip used to describe if a countermeasure was activated.
// If true then a countermeasure was activated. Otherwise, not.
//
// The global variable "extern UBYTE g_countermeasure".
var countermeasure bool

func init() {
	ptc = MaxAttempts
	for i := range cardPIN {
		cardPIN[i] = byte(i)
	}
}

// Checks if a successful attack authenticated the user regardless of the pin.
func OracleAuth(authenticated HardendBool) bool {
	return !countermeasure && authenticated == TrueHB
}

// Checks if a successful attack allowed more attempts than MaxAttempts.
func OraclePTC() bool {
	return !countermeasure && ptc >= MaxAttempts
}

func TriggerCountermeasure() {
	countermeasure = true
}

func PINCompare(a1 [PINSize]byte, a2 [PINSize]byte, size int) HardendBool {
	for i := 0; i < size; i++ {
		if a1[i] != a2[i] {
			return FalseHB
		}
	}
	return TrueHB
}

func VerifyPIN() HardendBool {
	if ptc > 0 {
		comp := PINCompare(userPIN, cardPIN, PINSize)
		if comp == TrueHB {
			ptc = MaxAttempts
			return TrueHB
		} else if comp == FalseHB {
			ptc--
			return FalseHB
		} else {
			TriggerCountermeasure()
		}
	}

	return FalseHB
}
