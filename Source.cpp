#pragma comment(linker,"\"/manifestdependency:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

#pragma comment(lib, "shlwapi")
#pragma comment(lib, "wininet")
#pragma comment(lib, "crypt32")

#include <windows.h>
#include <commctrl.h>
#include <shlwapi.h>
#include <wininet.h>
#include <map>
#include <string>
#include "json.hpp"

WCHAR szClassName[] = L"Window";

INT64 GetUnixTime()
{
	SYSTEMTIME systemtime;
	GetSystemTime(&systemtime);
	FILETIME filetime;
	SystemTimeToFileTime(&systemtime, &filetime);
	INT64 unixtime = filetime.dwHighDateTime;
	unixtime <<= 32;
	unixtime += filetime.dwLowDateTime;
	unixtime -= 116444736000000000L;
	unixtime /= 10000000L;
	return unixtime;
}

LPSTR CreateRandomString()
{
	HCRYPTPROV prov;
	if (CryptAcquireContext(&prov, NULL, NULL, PROV_RSA_FULL, 0)) {
		BYTE data[32] = {};
		CryptGenRandom(prov, sizeof(data), data);
		DWORD dwSize = 0;
		CryptBinaryToStringA(data, sizeof(data), CRYPT_STRING_BASE64, NULL, &dwSize);
		LPSTR random = (LPSTR)GlobalAlloc(GPTR, dwSize);
		if (random) {
			CryptBinaryToStringA(data, sizeof(data), CRYPT_STRING_BASE64, random, &dwSize);
			CryptReleaseContext(prov, 0);
			LPSTR p, q;
			for (p = random, q = random; *p; p++) {
				if (*p != '+' && *p != '/' && *p != '=' && *p != '\r' && *p != '\n') {
					*q++ = *p;
				}
			}
			*q = 0;
			return random;
		}
	}
	return 0;
}

int UrlEncode(LPCSTR src, LPSTR dst)
{
	DWORD idst = 0;
	for (DWORD isrc = 0; src[isrc] != '\0'; ++isrc) {
		LPCSTR lpszUnreservedCharacters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~";
		if (StrChrA(lpszUnreservedCharacters, src[isrc])) {
			if (dst) dst[idst] = (WCHAR)src[isrc];
			++idst;
		}
		else if (src[isrc] == ' ') {
			if (dst) dst[idst] = L'+';
			++idst;
		}
		else {
			if (dst) wsprintfA(&dst[idst], "%%%02X", src[isrc] & 0xFF);
			idst += 3;
		}
	}
	if (dst) dst[idst] = L'\0';
	++idst;
	return idst;
}

LPSTR CreateURLEncodeStrng(LPCSTR src)
{
	const int nSize = UrlEncode(src, 0);
	if (nSize) {
		LPSTR encoded = (LPSTR)GlobalAlloc(0, nSize);
		if (encoded) {
			UrlEncode(src, encoded);
			return encoded;
		}
	}
	return 0;
}

BOOL GetHMAC_SHA1(LPCSTR src, LPCSTR key, LPSTR output, DWORD size)
{
	BOOL ret = FALSE;

	DWORD keylen = lstrlenA(key);
	if (keylen >= 1024) {
		return FALSE;
	}

	struct {
		BLOBHEADER hdr;
		DWORD      len;
		BYTE       key[1024];
	} key_blob;

	HCRYPTPROV  hProv = NULL;
	HCRYPTHASH  hHash = NULL;
	HCRYPTKEY   hKey = NULL;
	HCRYPTHASH  hHmacHash = NULL;
	PBYTE       pbHash = NULL;
	DWORD       dwDataLen = 0;
	HMAC_INFO   HmacInfo;

	ZeroMemory(&HmacInfo, sizeof(HmacInfo));
	HmacInfo.HashAlgid = CALG_SHA1;

	if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, 0)) {
		goto ErrorExit;
	}

	ZeroMemory(&key_blob, sizeof(key_blob));

	key_blob.hdr.bType = PLAINTEXTKEYBLOB;
	key_blob.hdr.bVersion = CUR_BLOB_VERSION;
	key_blob.hdr.reserved = 0;
	key_blob.hdr.aiKeyAlg = CALG_RC2;
	key_blob.len = keylen;
	memcpy(key_blob.key, key, keylen);

	if (!CryptImportKey(hProv, (BYTE*)&key_blob, sizeof(key_blob), 0, CRYPT_IPSEC_HMAC_KEY, &hKey)) {
		goto ErrorExit;
	}

	if (!CryptCreateHash(hProv, CALG_HMAC, hKey, 0, &hHmacHash)) {
		goto ErrorExit;
	}

	if (!CryptSetHashParam(hHmacHash, HP_HMAC_INFO, (BYTE*)&HmacInfo, 0)) {
		goto ErrorExit;
	}

	if (!CryptHashData(hHmacHash, (LPCBYTE)src, lstrlenA(src), 0)) {
		goto ErrorExit;
	}

	if (!CryptGetHashParam(hHmacHash, HP_HASHVAL, NULL, &dwDataLen, 0)) {
		goto ErrorExit;
	}

	pbHash = (LPBYTE)GlobalAlloc(0, dwDataLen);
	if (NULL == pbHash) {
		goto ErrorExit;
	}

	if (!CryptGetHashParam(hHmacHash, HP_HASHVAL, pbHash, &dwDataLen, 0)) {
		goto ErrorExit;
	}

	CryptBinaryToStringA(pbHash, dwDataLen, CRYPT_STRING_BASE64, output, &size);
	LPSTR p = 0, q = 0;
	for (p = output, q = output; *p; p++) {
		if (*p != '\r' && *p != '\n') {
			*q++ = *p;
		}
	}
	*q = 0;
	ret = TRUE;

ErrorExit:
	if (hHmacHash)
		CryptDestroyHash(hHmacHash);
	if (hKey)
		CryptDestroyKey(hKey);
	if (hHash)
		CryptDestroyHash(hHash);
	if (hProv)
		CryptReleaseContext(hProv, 0);
	if (pbHash)
		GlobalFree(pbHash);

	return ret;
}

LPSTR CreateOAuthPram(const std::map<std::string, std::string>& m, LPCSTR consumer_secret, LPCSTR accesstoken_secret)
{
	std::string base;
	std::string parameter;

	for (auto it = m.begin(); it != m.end(); it++) {
		if (it != m.begin()) {
			base += "&";
			parameter += ",";
		}
		base += it->first;
		base += "=";
		base += it->second;
		parameter += it->first;
		parameter += "=";
		LPSTR encoded = CreateURLEncodeStrng(it->second.c_str());
		if (encoded) {
			parameter += encoded;
			GlobalFree(encoded);
		}
	}

	std::string src = "POST&";
	{
		LPCSTR url = "https://api.twitter.com/2/tweets";
		LPSTR encoded = CreateURLEncodeStrng(url);
		if (encoded) {
			src += encoded;
			src += "&";
			GlobalFree(encoded);
		}
	}
	{
		LPSTR encoded = CreateURLEncodeStrng(base.c_str());
		if (encoded) {
			src += encoded;
			GlobalFree(encoded);
		}
	}

	std::string key = "";
	key += consumer_secret;
	key += "&";
	key += accesstoken_secret;

	LPSTR lpszOAuthParam = 0;
	std::string strOAuthSignature;
	{
		CHAR output[1024] = {};
		if (GetHMAC_SHA1(src.c_str(), key.c_str(), output, _countof(output)) == TRUE) {
			LPSTR encoded = CreateURLEncodeStrng(output);
			if (encoded) {
				strOAuthSignature = encoded;
				GlobalFree(encoded);

				std::string strOAuthParam = "OAuth ";
				strOAuthParam += parameter;
				strOAuthParam += ",oauth_signature=";
				strOAuthParam += strOAuthSignature;

				lpszOAuthParam = (LPSTR)GlobalAlloc(0, strOAuthParam.size() + 1);
				if (lpszOAuthParam) {
					strcpy_s(lpszOAuthParam, strOAuthParam.size() + 1, strOAuthParam.c_str());
				}
			}
		}
	}

	return lpszOAuthParam;
}

BOOL tweet(HWND hWnd, LPCSTR lpszOAuthParam, LPCSTR szConsumerSecret, LPCSTR szAccessTokenSecret, LPCSTR lpszMessage)
{
	BOOL ret = FALSE;

	HINTERNET hInternet = InternetOpen(NULL, INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
	if (hInternet == NULL) {
		return FALSE;
	}
	HINTERNET hSession = InternetConnectW(hInternet, L"api.twitter.com", INTERNET_DEFAULT_HTTPS_PORT, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
	if (hSession == NULL) {
		InternetCloseHandle(hInternet);
		return FALSE;
	}
	HINTERNET hRequest = HttpOpenRequestW(hSession, L"POST", L"/2/tweets", NULL, NULL, NULL, INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_SECURE, 0);
	if (hRequest == NULL) {
		InternetCloseHandle(hSession);
		InternetCloseHandle(hInternet);
		return FALSE;
	}

	CHAR header[2048];
	wsprintfA(header, "Content-Type: application/json;\r\nAuthorization: %s;\r\n", lpszOAuthParam);

	nlohmann::json payload;
	payload["text"] = lpszMessage;

	if (HttpSendRequestA(hRequest, header, (DWORD)lstrlenA(header), (LPVOID)payload.dump().c_str(), (DWORD)payload.dump().size())) {
		BOOL bResult = FALSE;

		DWORD dwBufferSize;

		DWORD dwStatusCode = 0;
		dwBufferSize = sizeof(dwStatusCode);
		HttpQueryInfoW(hRequest, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &dwStatusCode, &dwBufferSize, 0);

		if (dwStatusCode != HTTP_STATUS_OK &&
			dwStatusCode != HTTP_STATUS_CREATED &&
			dwStatusCode != HTTP_STATUS_ACCEPTED &&
			dwStatusCode != HTTP_STATUS_PARTIAL &&
			dwStatusCode != HTTP_STATUS_NO_CONTENT &&
			dwStatusCode != HTTP_STATUS_RESET_CONTENT &&
			dwStatusCode != HTTP_STATUS_PARTIAL_CONTENT) {
			WCHAR szBuffer[256] = { 0 };
			dwBufferSize = _countof(szBuffer);
			HttpQueryInfoW(hRequest, HTTP_QUERY_CONTENT_LENGTH, szBuffer, &dwBufferSize, NULL);
			DWORD dwContentLength = _wtol(szBuffer);
			LPBYTE lpByte = (LPBYTE)GlobalAlloc(0, dwContentLength + 1);
			if (lpByte) {
				DWORD dwReadSize;
				InternetReadFile(hRequest, lpByte, dwContentLength, &dwReadSize);
				lpByte[dwReadSize] = 0;
				auto j = nlohmann::json::parse(lpByte);
				if (j.find("detail") != j.end()) {
					std::string error;
					error = "ポストできませんでした(";
					error += j["detail"].get<std::string>();
					error += ")";
					MessageBoxA(hWnd, error.c_str(), 0, MB_OK);
				}
				GlobalFree(lpByte);
			}
		}
		else {
			MessageBox(hWnd, L"ポストしました", L"確認", MB_OK);
			ret = TRUE;
		}
	}

	InternetCloseHandle(hRequest);
	InternetCloseHandle(hSession);
	InternetCloseHandle(hInternet);

	return ret;
}

LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
	static HWND hEditConsumerKey;
	static HWND hEditConsumerSecret;
	static HWND hEditAccessToken;
	static HWND hEditAccessTokenSecret;
	static HWND hEditMessage;
	static HWND hButton;
	switch (msg)
	{
	case WM_CREATE:
		hEditConsumerKey = CreateWindowEx(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_VISIBLE | WS_CHILD | WS_TABSTOP | ES_AUTOHSCROLL, 0, 0, 0, 0, hWnd, 0, ((LPCREATESTRUCT)lParam)->hInstance, 0);
		SendMessage(hEditConsumerKey, EM_SETCUEBANNER, TRUE, (LPARAM)L"Consumer Key");
		hEditConsumerSecret = CreateWindowEx(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_VISIBLE | WS_CHILD | WS_TABSTOP | ES_AUTOHSCROLL, 0, 0, 0, 0, hWnd, 0, ((LPCREATESTRUCT)lParam)->hInstance, 0);
		SendMessage(hEditConsumerSecret, EM_SETCUEBANNER, TRUE, (LPARAM)L"Consumer Secret");
		hEditAccessToken = CreateWindowEx(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_VISIBLE | WS_CHILD | WS_TABSTOP | ES_AUTOHSCROLL, 0, 0, 0, 0, hWnd, 0, ((LPCREATESTRUCT)lParam)->hInstance, 0);
		SendMessage(hEditAccessToken, EM_SETCUEBANNER, TRUE, (LPARAM)L"Access Token");
		hEditAccessTokenSecret = CreateWindowEx(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_VISIBLE | WS_CHILD | WS_TABSTOP | ES_AUTOHSCROLL, 0, 0, 0, 0, hWnd, 0, ((LPCREATESTRUCT)lParam)->hInstance, 0);
		SendMessage(hEditAccessTokenSecret, EM_SETCUEBANNER, TRUE, (LPARAM)L"Access Token Secret");
		hEditMessage = CreateWindowEx(WS_EX_CLIENTEDGE, L"EDIT", L"", WS_VISIBLE | WS_CHILD | WS_TABSTOP | ES_MULTILINE | ES_AUTOHSCROLL | ES_AUTOVSCROLL, 0, 0, 0, 0, hWnd, 0, ((LPCREATESTRUCT)lParam)->hInstance, 0);
		hButton = CreateWindow(L"BUTTON", L"ポスト", WS_VISIBLE | WS_CHILD | WS_TABSTOP, 0, 0, 0, 0, hWnd, (HMENU)IDOK, ((LPCREATESTRUCT)lParam)->hInstance, 0);
		break;
	case WM_SIZE:
		MoveWindow(hEditConsumerKey, 10, 10, 512, 32, TRUE);
		MoveWindow(hEditConsumerSecret, 10, 50, 512, 32, TRUE);
		MoveWindow(hEditAccessToken, 10, 90, 512, 32, TRUE);
		MoveWindow(hEditAccessTokenSecret, 10, 130, 512, 32, TRUE);
		MoveWindow(hEditMessage, 10, 170, 512, 256, TRUE);
		MoveWindow(hButton, 10, 436, 512, 32, TRUE);
		break;
	case WM_COMMAND:
		if (LOWORD(wParam) == IDOK) {
			CHAR szConsumerKey[256];
			CHAR szConsumerSecret[256];
			CHAR szAccessTokenKey[256];
			CHAR szAccessTokenSecret[256];

			GetWindowTextA(hEditConsumerKey, szConsumerKey, 256);
			GetWindowTextA(hEditConsumerSecret, szConsumerSecret, 256);
			GetWindowTextA(hEditAccessToken, szAccessTokenKey, 256);
			GetWindowTextA(hEditAccessTokenSecret, szAccessTokenSecret, 256);

			std::map<std::string, std::string> m;
			m["oauth_consumer_key"] = szConsumerKey;
			LPSTR lpszNonce = CreateRandomString();
			m["oauth_nonce"] = lpszNonce;
			GlobalFree(lpszNonce);
			m["oauth_signature_method"] = "HMAC-SHA1";
			CHAR szTimestamp[16] = {};
			wsprintfA(szTimestamp, "%I64d", GetUnixTime());
			m["oauth_timestamp"] = szTimestamp;
			m["oauth_version"] = "1.0";
			m["oauth_token"] = szAccessTokenKey;

			LPSTR lpszOAuthParam = CreateOAuthPram(m, szConsumerSecret, szAccessTokenSecret);
			if (lpszOAuthParam) {
				DWORD size = GetWindowTextLength(hEditMessage);
				LPWSTR lpszMessageW = (LPWSTR)GlobalAlloc(0, sizeof(WCHAR) * (size + 1));
				if (lpszMessageW) {
					GetWindowText(hEditMessage, lpszMessageW, size + 1);
					size = WideCharToMultiByte(CP_UTF8, 0, lpszMessageW, -1, 0, 0, 0, 0);
					LPSTR lpszMessageA = (LPSTR)GlobalAlloc(GPTR, size);
					if (lpszMessageA) {
						WideCharToMultiByte(CP_UTF8, 0, lpszMessageW, -1, lpszMessageA, size, 0, 0);
						tweet(hWnd, lpszOAuthParam, szConsumerSecret, szAccessTokenSecret, lpszMessageA);
						GlobalFree(lpszMessageA);
					}
					GlobalFree(lpszMessageW);
				}
				GlobalFree(lpszOAuthParam);
			}
		}
		break;
	case WM_CLOSE:
		DestroyWindow(hWnd);
		break;
	case WM_DESTROY:
		PostQuitMessage(0);
		break;
	default:
		return DefDlgProc(hWnd, msg, wParam, lParam);
	}
	return 0;
}

int WINAPI wWinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance, _In_ LPWSTR lpCmdLine, _In_ int nShowCmd)
{
	MSG msg;
	WNDCLASS wndclass = {
		CS_HREDRAW | CS_VREDRAW,
		WndProc,
		0,
		DLGWINDOWEXTRA,
		hInstance,
		0,
		LoadCursor(0,IDC_ARROW),
		0,
		0,
		szClassName
	};
	RegisterClass(&wndclass);

	RECT rect = { 0,0,532,478 };
	AdjustWindowRect(&rect, WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX | WS_CLIPCHILDREN, FALSE);

	HWND hWnd = CreateWindow(
		szClassName,
		TEXT("Xにポストする"),
		WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX | WS_CLIPCHILDREN,
		CW_USEDEFAULT,
		0,
		rect.right - rect.left,
		rect.bottom - rect.top,
		0,
		0,
		hInstance,
		0
	);
	ShowWindow(hWnd, SW_SHOWDEFAULT);
	UpdateWindow(hWnd);
	while (GetMessage(&msg, 0, 0, 0)) {
		if (!IsDialogMessage(hWnd, &msg)) {
			TranslateMessage(&msg);
			DispatchMessage(&msg);
		}
	}
	return (int)msg.wParam;
}
