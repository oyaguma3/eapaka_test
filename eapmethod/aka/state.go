package aka

import "github.com/oyaguma3/eapaka_test/eap"

// phase は、1 回の EAP 交換の中での EAP-AKA/AKA' の進み具合。
type phase int

const (
	phaseIdle           phase = iota // まだ EAP-AKA/AKA' の要求を受けていない
	phaseIdentity                    // AKA-Identity に応答した
	phaseKdfNegotiation              // AT_KDF だけの応答を送り、サーバの再提示を待っている
	phaseSyncFailure                 // Synchronization-Failure を送り、新しい Challenge を待っている
	phaseChallenged                  // Challenge に AT_RES で応答した（メソッドとしては完了）
	phaseFailed                      // Authentication-Reject か Client-Error を送った
)

// akaSession は、1 回の EAP 交換の間だけ保持する状態（設計書 §4.1）。
// Method は実行ごとに作り直すので、Method が 1 つずつ持つ。
type akaSession struct {
	phase          phase
	identityRounds int      // AKA-Identity の往復回数
	kdfOffer       []uint16 // AT_KDF 交渉の元の offer（再提示の検証に使う）
	kdfSelected    uint16   // AT_KDF だけの応答で選んだ KDF

	emptyKdfInputReported bool // 空の AT_KDF_INPUT を A-13 として記録済み
}

// methodState は、EAP 層の判定（R-05 など）に使うメソッドの進み具合に変換する。
func (p phase) methodState() eap.MethodState {
	switch p {
	case phaseChallenged:
		return eap.MethodCompleted
	case phaseFailed:
		return eap.MethodFailed
	default:
		return eap.MethodInProgress
	}
}
