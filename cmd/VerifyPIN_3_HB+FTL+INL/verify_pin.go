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

func VerifyPIN() HardendBool {
	if ptc > 0 {
		/* Inl (Inlining): PINCompare */
		status := FalseHB
		diff := FalseHB

		i := 0
		for i = 0; i < PINSize; i++ {
			if userPIN[i] != cardPIN[i] {
				diff = TrueHB
			}
		}

		if i != PINSize {
			TriggerCountermeasure()
		}

		if diff == FalseHB {
			status = TrueHB
		} else {
			status = FalseHB
		}
		/* End Inline */

		if status == TrueHB {
			ptc = MaxAttempts
			return TrueHB
		} else if status == FalseHB {
			ptc--
			return FalseHB
		} else {
			TriggerCountermeasure()
		}
	}

	return FalseHB
}
