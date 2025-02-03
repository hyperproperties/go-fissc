package main

import (
	"testing"
)

func TestVerifyPIN_Success(t *testing.T) {
	ptc = MaxAttempts
	countermeasure = false
	userPIN = cardPIN

	if !VerifyPIN() {
		t.Errorf("Expected successful authentication with correct PIN")
	}

	if ptc != MaxAttempts {
		t.Errorf("Expected ptc to reset to MaxAttempts, got %d", ptc)
	}
}

func TestVerifyPIN_Failure(t *testing.T) {
	ptc = MaxAttempts
	countermeasure = false
	userPIN = [PINSize]byte{9, 9, 9, 9}

	for i := 0; i < MaxAttempts; i++ {
		if VerifyPIN() {
			t.Errorf("Expected authentication to fail with incorrect PIN")
		}
	}

	if ptc != 0 {
		t.Errorf("Expected ptc to be 0 after %d failed attempts, got %d", MaxAttempts, ptc)
	}
}

func TestVerifyPIN_Countermeasure(t *testing.T) {
	ptc = MaxAttempts
	countermeasure = false

	TriggerCountermeasure()
	if !countermeasure {
		t.Errorf("Expected countermeasure to be activated")
	}

	if OracleAuth(true) {
		t.Errorf("Expected OracleAuth to return false when countermeasure is triggered")
	}
}

func TestVerifyPIN_ResetAfterSuccess(t *testing.T) {
	userPIN = [PINSize]byte{9, 9, 9, 9}

	VerifyPIN() // Should reduce ptc to 0
	if ptc != MaxAttempts-1 {
		t.Errorf("Expected ptc to be 0 after failed attempt")
	}

	userPIN = cardPIN
	VerifyPIN()

	if ptc != MaxAttempts {
		t.Errorf("Expected ptc to reset to MaxAttempts after correct PIN, got %d", ptc)
	}
}

func TestVerifyPIN_EdgeCase_LastAttemptSuccess(t *testing.T) {
	ptc = 1
	userPIN = cardPIN

	if !VerifyPIN() {
		t.Errorf("Expected successful authentication on last attempt")
	}

	if ptc != MaxAttempts {
		t.Errorf("Expected ptc to reset to MaxAttempts after correct PIN on last attempt, got %d", ptc)
	}
}

func TestOraclePTC(t *testing.T) {
	ptc = MaxAttempts
	countermeasure = false

	if !OraclePTC() {
		t.Errorf("Expected OraclePTC to return true when ptc is at MaxAttempts and no countermeasure is active")
	}

	ptc--
	if OraclePTC() {
		t.Errorf("Expected OraclePTC to return false when ptc is less than MaxAttempts")
	}

	TriggerCountermeasure()
	if OraclePTC() {
		t.Errorf("Expected OraclePTC to return false when countermeasure is triggered")
	}
}
