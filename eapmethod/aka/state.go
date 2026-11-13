package aka

import "github.com/oyaguma3/eapaka_test/eap"

// phase は、1 回の EAP 交換の中での EAP-AKA/AKA' の進み具合。
type phase int

const (
	phaseIdle           phase = iota // まだ EAP-AKA/AKA' の要求を受けていない
	phaseIdentity                    // AKA-Identity に応答した
	phaseKdfNegotiation              // AT_KDF だけの応答を送り、サーバの再提示を待っている
	phaseSyncFailure                 // Synchronization-Failure を送り、新しい Challenge を待っている
	phaseAwaitingResult              // AT_RESULT_IND を使って Challenge に応答し、成功通知を待っている
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

	keys sessionKeys // 直近のフル認証で導出した鍵

	identityMsgs       [][]byte // AKA-Identity の Request / Response（送受信したままの形。AT_CHECKCODE 用）
	permanentRequested bool     // AT_PERMANENT_ID_REQ を受けた（規則 A-01）

	nextReauthID        string // フル認証の AT_ENCR_DATA で受け取った AT_NEXT_REAUTH_ID
	reauthed            bool   // 再認証を終えた（その後の P=0 の通知は暗号化された AT_COUNTER を持つ）
	counter             uint16 // 再認証で受け入れた AT_COUNTER
	counterTooSmallSent bool   // AT_COUNTER_TOO_SMALL を送った（規則 A-11）

	resultInd     bool // AT_RESULT_IND をサーバとピアの両方が使った
	notifications int  // 受け取った AKA-Notification の数
	peerError     bool // Client-Error か Authentication-Reject を送った
}

// sessionKeys はフル認証で導出した鍵。ログやトレースには出さない。
type sessionKeys struct {
	kEncr, kAut, msk, emsk []byte
	mk                     []byte // EAP-AKA の再認証の鍵導出に使う
	kRe                    []byte // EAP-AKA' の再認証の鍵導出に使う
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
