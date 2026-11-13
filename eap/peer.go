package eap

import (
	"fmt"
	"maps"
	"slices"

	"github.com/oyaguma3/eapaka_test/conformance"
	"github.com/oyaguma3/eapaka_test/idstore"
)

// Session holds outer/inner identity data for the current EAP session.
type Session struct {
	OuterIdentity string
	InnerIdentity string

	// Conformance はサーバの RFC 違反を記録する。nil なら記録しない。
	Conformance *conformance.Recorder
	// Obs は期待値の判定とトレースに使う観測結果（設計書 §4.1）。
	Obs Observations
	// OnWarn は、違反ではないが知らせたい事柄（設定値との不一致など）を受け取る。
	OnWarn func(msg string)

	// Pending は、Access-Accept を受けたら識別子ストアに保存する値（受け取った仮名など）。
	Pending PendingIDs

	// MSK は、メソッドが最後に導出した MSK（64 バイト）。MS-MPPE 鍵との照合（X2）に使う。
	// ログやトレースには出さない。
	MSK []byte
}

// Warnf は OnWarn に警告を渡す。OnWarn が nil なら何もしない。
func (s *Session) Warnf(format string, args ...any) {
	if s != nil && s.OnWarn != nil {
		s.OnWarn(fmt.Sprintf(format, args...))
	}
}

// MethodState は EAP メソッドの進み具合。
type MethodState int

const (
	MethodNotStarted MethodState = iota // メソッドの要求をまだ受けていない
	MethodInProgress                    // メソッドの途中
	MethodCompleted                     // ピアとしてメソッドを完了した（成功を受け取ってよい）
	MethodFailed                        // ピアが Authentication-Reject や Client-Error を送った
)

func (s MethodState) String() string {
	switch s {
	case MethodNotStarted:
		return "not_started"
	case MethodInProgress:
		return "in_progress"
	case MethodCompleted:
		return "completed"
	case MethodFailed:
		return "failed"
	default:
		return fmt.Sprintf("MethodState(%d)", int(s))
	}
}

// Observations は 1 回の EAP 交換で観測した結果。
type Observations struct {
	Method MethodState
	// Faults は注入した異常（X4）。"at/action" の形で記録する。
	Faults []string
	// MSKMatch は MS-MPPE 鍵を復号した値と MSK の照合結果（X2）。照合しなかったときは nil。
	MSKMatch *bool
	// MSKDetail は、照合しなかった理由か、一致しなかった理由。
	MSKDetail string
	// Bidding は受け取った AT_BIDDING の観測結果（RFC 9048 §4）。受け取らなければ nil。
	Bidding *BiddingObs
	// Naks は送った EAP-Response/Nak の内容（提示されたタイプと、希望したタイプ）。
	Naks []NakObs
	// Notifications は受け取った AKA-Notification（RFC 4187 §6）。
	Notifications []NotificationObs
	// ResultInd は、AT_RESULT_IND をサーバとピアの両方が使った（成功通知を待つ）こと（RFC 4187 §6.2）。
	ResultInd bool
	// PeerError は、ピアが Client-Error か Authentication-Reject を送ったこと（規則 A-10 の判定に使う）。
	PeerError bool
	// EAPNotifications は、RFC 3748 の Notification（Type 2）で受け取った表示用のメッセージ。
	EAPNotifications []string
	// IdentityRequests は、受け取った AKA-Identity の要求の種類（any / fullauth / permanent / none）。
	IdentityRequests []string
	// NextPseudonym と NextReauthID は、AT_ENCR_DATA で次回の仮名・再認証 ID を受け取ったか。
	NextPseudonym bool
	NextReauthID  bool
	// Checkcode は AT_CHECKCODE の検証結果（"verified"、"mismatch"、受け取らなければ ""）。
	Checkcode string
	// AuthType は行った認証の種類（"full" か "reauth"）。
	AuthType string
	// ReauthCounter は、再認証で受け入れた AT_COUNTER。
	ReauthCounter uint16
	// CounterTooSmallSent は、AT_COUNTER_TOO_SMALL を送ったこと（RFC 4187 §5.5）。
	CounterTooSmallSent bool
	// SessionID と PeerID は、EAP のエクスポートパラメータ（X8、RFC 5247 付録 A、RFC 9048 §6）。
	// EAP-AKA の再認証の Session-Id は RFC に定義がないので空。
	SessionID []byte
	PeerID    string
	// KeyName は、Access-Accept の EAP-Key-Name と Session-Id の照合結果
	// （"match"、"mismatch"、ピアに Session-Id がなければ "undefined"、属性がなければ ""）。
	KeyName string
}

// NotificationObs は AKA-Notification の記録。Code は S・P ビットを含む 16 bit の値。
type NotificationObs struct {
	Code uint16
	S, P bool
}

// SuccessNotified は成功通知（32768）を受け取ったかを返す。
func (o Observations) SuccessNotified() bool {
	return slices.ContainsFunc(o.Notifications, func(n NotificationObs) bool { return n.Code == 32768 })
}

// FailureNotified は失敗通知（S=0）を受け取ったかを返す。
func (o Observations) FailureNotified() bool {
	return slices.ContainsFunc(o.Notifications, func(n NotificationObs) bool { return !n.S })
}

// BiddingObs は AT_BIDDING の観測結果。
type BiddingObs struct {
	Method uint8  // AT_BIDDING を含んでいたパケットの EAP タイプ
	DBit   bool   // D ビット（サーバが AKA' に対応している）
	Action string // ピアの動作: "reject"（Authentication-Reject）か "ignore"
}

// NakObs は送った Nak の記録。
type NakObs struct {
	Offered  uint8   // サーバが提示したタイプ
	Proposed []uint8 // Nak で希望したタイプ（希望がなければ [0]）
}

// Method handles EAP method-specific requests.
type Method interface {
	Type() uint8
	Handle(req Packet, sess *Session) (*Packet, error)
}

// MethodMismatchError indicates the received method type differs from expected.
type MethodMismatchError struct {
	Expected uint8
	Received uint8
	Policy   MethodMismatchPolicy
}

func (e *MethodMismatchError) Error() string {
	return fmt.Sprintf("eap: method mismatch expected=%d received=%d policy=%s", e.Expected, e.Received, e.Policy)
}

// Peer handles EAP requests and dispatches to registered methods.
type Peer struct {
	Session        *Session
	Methods        map[uint8]Method
	MethodPolicy   MethodMismatchPolicy
	ExpectedMethod *uint8
	Warn           func(error)

	// MethodPreference は、使ってよい EAP メソッドを希望順に並べたもの（X5、RFC 3748 §5.3.1）。
	// 空なら、登録したメソッドすべてを AKA' → AKA の順で希望する。
	MethodPreference []uint8
	// NakOn のタイプを提示されたら、NakPropose を希望する Nak を返す（X5 の強制 Nak）。
	// サーバを別のメソッドに誘導する試験（AT_BIDDING など）に使う。
	NakOn      []uint8
	NakPropose []uint8

	// method は最初に応答したメソッドのタイプ（R-06 の検査用）。
	method uint8
	// nakZero は、希望なし（0）の Nak を送ったこと（R-08 の検査用）。
	nakZero bool
}

// NewPeer creates a peer with the given session and methods.
func NewPeer(sess *Session, methods ...Method) *Peer {
	peer := &Peer{Session: sess, Methods: make(map[uint8]Method)}
	for _, method := range methods {
		if method != nil {
			peer.Methods[method.Type()] = method
		}
	}
	return peer
}

// Handle processes a server request and returns the response, if any.
func (p *Peer) Handle(req Packet) (*Packet, error) {
	if p == nil {
		return nil, fmt.Errorf("eap: peer is nil")
	}
	if req.Code == CodeSuccess || req.Code == CodeFailure {
		return nil, nil
	}
	if req.Code != CodeRequest {
		return nil, fmt.Errorf("eap: unsupported code %d", req.Code)
	}

	sess := p.Session
	if sess == nil {
		sess = &Session{}
	}
	if p.nakZero {
		// RFC 3748 §5.3.1: 0 の Nak を受けたサーバは、次の Request を送らないほうがよい
		sess.Conformance.Report("R-08", "EAP-Request type %d received after a Nak with type 0", req.Type)
	}

	if req.Type == TypeIdentity {
		return identityResponse(req.Identifier, sess.OuterIdentity)
	}
	if req.Type == TypeNotify {
		// RFC 3748 §5.2: Type-Data が空の Notification で応答する（Nak で応答してはならない）
		sess.Obs.EAPNotifications = append(sess.Obs.EAPNotifications, string(req.TypeData))
		sess.Warnf("EAP Notification received: %q", req.TypeData)
		return &Packet{Code: CodeResponse, Identifier: req.Identifier, Type: TypeNotify}, nil
	}

	// Nak はメソッドに応答する前だけ送れる（RFC 3748 §5.3.1）
	if p.method == 0 {
		if proposed, ok := p.nakFor(req.Type); ok {
			sess.Obs.Naks = append(sess.Obs.Naks, NakObs{Offered: req.Type, Proposed: proposed})
			p.nakZero = slices.Equal(proposed, []uint8{0})
			return &Packet{Code: CodeResponse, Identifier: req.Identifier, Type: TypeNak, TypeData: proposed}, nil
		}
	}

	method := p.Methods[req.Type]
	if method == nil {
		return nil, fmt.Errorf("eap: unsupported method %d", req.Type)
	}

	switch {
	case p.method == 0:
		p.method = req.Type
	case p.method != req.Type:
		sess.Conformance.Report("R-06", "EAP method switched from type %d to %d", p.method, req.Type)
	}

	if p.ExpectedMethod != nil && *p.ExpectedMethod != req.Type {
		mismatch := &MethodMismatchError{Expected: *p.ExpectedMethod, Received: req.Type, Policy: p.MethodPolicy}
		switch p.MethodPolicy {
		case MethodMismatchStrict:
			return nil, mismatch
		case MethodMismatchWarn:
			if p.Warn != nil {
				p.Warn(mismatch)
			}
		}
	}

	return method.Handle(req, sess)
}

func identityResponse(identifier uint8, identity string) (*Packet, error) {
	if identity == "" {
		return nil, fmt.Errorf("eap: outer identity is required")
	}
	return &Packet{
		Code:       CodeResponse,
		Identifier: identifier,
		Type:       TypeIdentity,
		TypeData:   []byte(identity),
	}, nil
}

// nakFor は、提示されたタイプ t に Nak で応答するかと、Nak で希望するタイプを返す。
func (p *Peer) nakFor(t uint8) ([]uint8, bool) {
	if slices.Contains(p.NakOn, t) {
		if len(p.NakPropose) == 0 {
			return []uint8{0}, true
		}
		return slices.Clone(p.NakPropose), true
	}
	preference := p.MethodPreference
	if len(preference) == 0 {
		preference = slices.Sorted(maps.Keys(p.Methods))
		slices.Reverse(preference) // AKA'（50）を AKA（23）より先に希望する
	}
	if p.Methods[t] != nil && slices.Contains(preference, t) {
		return nil, false
	}
	var proposed []uint8
	for _, m := range preference {
		if p.Methods[m] != nil && m != t {
			proposed = append(proposed, m)
		}
	}
	if len(proposed) == 0 {
		// 希望するタイプがない（RFC 3748 §5.3.1）
		proposed = []uint8{0}
	}
	return proposed, true
}

// PendingIDs は、認証が成功したら保存する識別子（設計書 §4.1 のコミットの規則）。
type PendingIDs struct {
	Method    uint8  // 発行したメソッドの EAP タイプ
	Pseudonym string // AT_NEXT_PSEUDONYM（レルムなし）。空なら受け取っていない
	// AuthDone は、ピアとしてフル認証か再認証を終えたこと。このとき Reauth で再認証の状態を置き換える。
	AuthDone bool
	// Reauth は次回の再認証コンテキスト。nil なら再認証の状態を破棄する（RFC 4187 §5.3）。
	Reauth *idstore.Reauth
}
