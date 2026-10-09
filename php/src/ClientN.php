<?php
declare(strict_types=1);

/** Server-to-server calls to the ClientN API. The API key never leaves your server. */
class ClientN
{
    public function __construct(private string $base, private string $key) {}

    /** @return array{status:int, body:?array} */
    protected function call(string $method, string $path, ?array $payload = null): array
    {
        $ch = curl_init(rtrim($this->base, '/') . $path);
        $opts = [
            CURLOPT_CUSTOMREQUEST => $method, CURLOPT_RETURNTRANSFER => true, CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_TIMEOUT => 8, CURLOPT_CONNECTTIMEOUT => 4,
            CURLOPT_HTTPHEADER => ['Authorization: Bearer ' . $this->key, 'Accept: application/json', 'Content-Type: application/json'],
        ];
        if ($method === 'POST') { $opts[CURLOPT_POSTFIELDS] = $payload === null ? '' : json_encode($payload); }
        curl_setopt_array($ch, $opts);
        $text = curl_exec($ch);
        $status = (int)curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        curl_close($ch);
        $body = is_string($text) ? json_decode($text, true) : null;
        return ['status' => $status, 'body' => is_array($body) ? $body : null];
    }

    /**
     * Start a sign-in. $opts is the JSON body: flow, return_url, code_challenge, end_user_ip, end_user_agent.
     * Returns session_id, flow, confirm_url, qr_png_base64, match_code, expires_at.
     */
    public function createSession(array $opts = []): array
    {
        $r = $this->call('POST', '/api/v1/sessions', $opts);
        if ($r['status'] !== 201 || empty($r['body']['session_id'])) { throw new RuntimeException('ClientN refused to start a session: ' . $r['status']); }
        return $r['body'];
    }
    /** Recovery: ask ClientN what happened to one of YOUR sessions (Bearer key required). */
    public function getSession(string $sessionId): array { return $this->call('GET', '/api/v1/sessions/' . rawurlencode($sessionId)); }
    /** Redirect flow: trade the one-time code + this browser's verifier for the signed result (works once). */
    public function exchange(string $sessionId, string $code, string $verifier): array
    {
        return $this->call('POST', '/api/v1/sessions/' . rawurlencode($sessionId) . '/exchange', ['code' => $code, 'code_verifier' => $verifier]);
    }
}
