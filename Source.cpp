#pragma comment(linker,"\"/manifestdependency:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

#pragma comment(lib, "shlwapi")
#pragma comment(lib, "wininet")
#pragma comment(lib, "crypt32")
#pragma comment(lib, "gdiplus")
#pragma comment(lib, "dwmapi")

#include <windows.h>
#include <windowsx.h>
#include <dwmapi.h>
#include <commctrl.h>
#include <shlwapi.h>
#include <shlobj.h>
#include <wininet.h>
#include <gdiplus.h>
#include <map>
#include <string>
#include "json.hpp"
#include "resource.h"

using namespace Gdiplus;

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

LPSTR CreateOAuthPram(const std::map<std::string, std::string>& m, LPCSTR url, LPCSTR consumer_secret, LPCSTR access_token_secret, BOOL bIncludeQueryParameter = TRUE)
{
	std::string base;
	std::map<std::string, std::string> parameter;

	for (auto it = m.begin(); it != m.end(); it++) {
		if (it != m.begin()) {
			base += "&";
		}
		base += it->first;
		base += "=";
		base += it->second;
		LPSTR encoded = CreateURLEncodeStrng(it->second.c_str());
		if (encoded) {
			parameter[it->first] = encoded;
			GlobalFree(encoded);
		}
	}

	std::string src;
	if (bIncludeQueryParameter) {
		src += "POST&";
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
	key += access_token_secret;

	LPSTR lpszOAuthParam = 0;
	{
		CHAR output[1024] = {};
		if (GetHMAC_SHA1(src.c_str(), key.c_str(), output, _countof(output)) == TRUE) {
			LPSTR encoded = CreateURLEncodeStrng(output);
			if (encoded) {
				std::string strOAuthParam = "OAuth ";
				for (auto it = parameter.begin(); it != parameter.end(); it++) {
					if (it != parameter.begin()) {
						strOAuthParam += ",";
					}
					strOAuthParam += it->first;
					strOAuthParam += "=";
					strOAuthParam += it->second;
				}
				strOAuthParam += ",oauth_signature=";
				strOAuthParam += encoded;
				GlobalFree(encoded);
				lpszOAuthParam = (LPSTR)GlobalAlloc(0, strOAuthParam.size() + 1);
				if (lpszOAuthParam) {
					strcpy_s(lpszOAuthParam, strOAuthParam.size() + 1, strOAuthParam.c_str());
				}
			}
		}
	}

	return lpszOAuthParam;
}

std::string send(HWND hWnd, LPCWSTR lpszServerName, LPCWSTR lpszObjectName, LPCSTR lpszOAuthParam, LPCSTR lpszHeader, LPCBYTE lpBody, DWORD dwBodySize)
{
	std::string ret;

	HINTERNET hInternet = InternetOpen(NULL, INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
	if (hInternet == NULL) {
		return ret;
	}
	HINTERNET hSession = InternetConnectW(hInternet, lpszServerName, INTERNET_DEFAULT_HTTPS_PORT, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
	if (hSession == NULL) {
		InternetCloseHandle(hInternet);
		return ret;
	}
	HINTERNET hRequest = HttpOpenRequestW(hSession, L"POST", lpszObjectName, NULL, NULL, NULL, INTERNET_FLAG_NO_CACHE_WRITE | INTERNET_FLAG_SECURE, 0);
	if (hRequest == NULL) {
		InternetCloseHandle(hSession);
		InternetCloseHandle(hInternet);
		return ret;
	}

	CHAR header[2048];
	wsprintfA(header, "Authorization: %s;\r\n", lpszOAuthParam);
	lstrcatA(header, lpszHeader);

	if (HttpSendRequestA(hRequest, header, (DWORD)lstrlenA(header), (LPVOID)lpBody, (DWORD)dwBodySize)) {
		BOOL bResult = FALSE;

		DWORD dwBufferSize;

		DWORD dwStatusCode = 0;
		dwBufferSize = sizeof(dwStatusCode);
		HttpQueryInfoW(hRequest, HTTP_QUERY_STATUS_CODE | HTTP_QUERY_FLAG_NUMBER, &dwStatusCode, &dwBufferSize, 0);

		DWORD dwContentLength = 0;
		dwBufferSize = sizeof(dwContentLength);
		HttpQueryInfoW(hRequest, HTTP_QUERY_CONTENT_LENGTH | HTTP_QUERY_FLAG_NUMBER, &dwContentLength, &dwBufferSize, NULL);
		if (dwContentLength > 0) {
			LPBYTE lpByte = (LPBYTE)GlobalAlloc(0, dwContentLength + 1);
			if (lpByte) {
				DWORD dwReadSize;
				InternetReadFile(hRequest, lpByte, dwContentLength, &dwReadSize);
				lpByte[dwReadSize] = 0;
				auto j = nlohmann::json::parse(lpByte);

				if (dwStatusCode != HTTP_STATUS_OK &&
					dwStatusCode != HTTP_STATUS_CREATED &&
					dwStatusCode != HTTP_STATUS_ACCEPTED &&
					dwStatusCode != HTTP_STATUS_PARTIAL &&
					dwStatusCode != HTTP_STATUS_NO_CONTENT &&
					dwStatusCode != HTTP_STATUS_RESET_CONTENT &&
					dwStatusCode != HTTP_STATUS_PARTIAL_CONTENT) {
					if (j.find("detail") != j.end()) {
						std::string error;
						error = "ポストできませんでした(ステータスコード:";
						error += std::to_string(dwStatusCode);
						error += ", エラー詳細:";
						error += j["detail"].get<std::string>();
						error += ")";
						MessageBoxA(hWnd, error.c_str(), 0, MB_OK);
					}
					else if ((j.find("error") != j.end())) {
						std::string error;
						error = "ポストできませんでした(ステータスコード:";
						error += std::to_string(dwStatusCode);
						error += ", エラー詳細:";
						error += j["error"].get<std::string>();
						error += ")";
						MessageBoxA(hWnd, error.c_str(), 0, MB_OK);
					}
					else if ((j.find("errors") != j.end())) {
						std::string error;
						error = "ポストできませんでした(ステータスコード:";
						error += std::to_string(dwStatusCode);
						error += ", エラー詳細:";
						for (auto& e : j["errors"]) {
							error += e["message"].get<std::string>();
							error += "\n";
						}
						error += ")";
						MessageBoxA(hWnd, error.c_str(), 0, MB_OK);
					}
					else {
						std::string error;
						error = "ポストできませんでした(ステータスコード:";
						error += std::to_string(dwStatusCode);
						error += ")";
						MessageBoxA(hWnd, error.c_str(), 0, MB_OK);
					}
				}
				else {
					if (j.find("media_id_string") != j.end()) {
						ret = j["media_id_string"];
					}
					else if (j.find("data") != j.end()) {
						auto data = j["data"];
						if (data.find("id") != data.end()) {
							ret = data["id"];
						}
					}
				}

				GlobalFree(lpByte);
			}
		}
		else {
			std::string error;
			error = "ポストできませんでした(ステータスコード:";
			error += std::to_string(dwStatusCode);
			error += ")";
			MessageBoxA(hWnd, error.c_str(), 0, MB_OK);
		}
	}

	InternetCloseHandle(hRequest);
	InternetCloseHandle(hSession);
	InternetCloseHandle(hInternet);

	return ret;
}

std::string image_upload(HWND hWnd, LPCSTR lpszOAuthParam, LPCBYTE lpByte)
{
	LPCSTR boundary = "AaB03x";
	DWORD dwBoundarySize = (DWORD)lstrlenA(boundary);
	DWORD dwOrgSize = (DWORD)GlobalSize((HGLOBAL)lpByte);
	LPCSTR lpszContentDisposition = "Content-Disposition: form-data; name=\"media\"; filename=\"media\"";
	DWORD dwContentDispositionSize = (DWORD)lstrlenA(lpszContentDisposition);
	LPCSTR lpszContentType = "Content-Type: image/png;";
	DWORD dwContentTypeSize = (DWORD)lstrlenA(lpszContentType);

	DWORD dwBodySize = 2/* ハイフン*2 */ + dwBoundarySize + 2/* 改行 */
		+ dwContentDispositionSize + 2/* 改行 */
		+ dwContentTypeSize + 2/* 改行 */
		+ 2/* 改行 */
		+ dwOrgSize 
		+ 2/* 改行 */
		+ 2/* ハイフン*2 */ + dwBoundarySize + 2/* ハイフン*2 */ + 2/* 改行 */;

	LPBYTE lpszBody = (LPBYTE)GlobalAlloc(0, dwBodySize + 1);
	if (lpszBody == NULL) {
		return std::string();
	}

	DWORD pos = 0;
	CopyMemory(lpszBody + pos, "--", 2);
	pos += 2;
	CopyMemory(lpszBody + pos, boundary, dwBoundarySize);
	pos += dwBoundarySize;
	CopyMemory(lpszBody + pos, "\r\n", 2);
	pos += 2;
	CopyMemory(lpszBody + pos, lpszContentDisposition, dwContentDispositionSize);
	pos += dwContentDispositionSize;
	CopyMemory(lpszBody + pos, "\r\n", 2);
	pos += 2;
	CopyMemory(lpszBody + pos, lpszContentType, dwContentTypeSize);
	pos += dwContentTypeSize;
	CopyMemory(lpszBody + pos, "\r\n", 2);
	pos += 2;
	CopyMemory(lpszBody + pos, "\r\n", 2);
	pos += 2;
	CopyMemory(lpszBody + pos, lpByte, dwOrgSize);
	pos += dwOrgSize;
	CopyMemory(lpszBody + pos, "\r\n", 2);
	pos += 2;
	CopyMemory(lpszBody + pos, "--", 2);
	pos += 2;
	CopyMemory(lpszBody + pos, boundary, dwBoundarySize);
	pos += dwBoundarySize;
	CopyMemory(lpszBody + pos, "--", 2);
	pos += 2;
	CopyMemory(lpszBody + pos, "\r\n", 2);
	pos += 2;

	std::string ret = send(hWnd, L"upload.twitter.com", L"/1.1/media/upload.json", lpszOAuthParam, "Content-Type: multipart/form-data; boundary=AaB03x", lpszBody, dwBodySize);

	GlobalFree(lpszBody);

	return ret;
}

std::string tweet(HWND hWnd, LPCSTR lpszOAuthParam, LPCSTR lpszMessage, const std::vector<std::string> &media_ids)
{
	nlohmann::json payload;
	payload["text"] = lpszMessage;
	if (media_ids.size() > 0) {
		payload["media"]["media_ids"] = media_ids;
	}
	std::string strPayload = payload.dump();
	return send(hWnd, L"api.twitter.com", L"/2/tweets", lpszOAuthParam, "Content-Type: application/json", (LPCBYTE)strPayload.c_str(), (DWORD)strPayload.size());
}

class BitmapEx : public Gdiplus::Bitmap {
public:
	LPBYTE m_lpByte;
	DWORD m_nSize;
	BitmapEx(IN HBITMAP hbm)
		: Gdiplus::Bitmap::Bitmap(hbm, 0)
		, m_lpByte(0), m_nSize(0) {
		Gdiplus::Status OldlastResult = GetLastStatus();
		if (OldlastResult == Gdiplus::Ok) {
			GUID guid;
			if (GetRawFormat(&guid) == Gdiplus::Ok) {
			}
		}
		else {
			lastResult = OldlastResult;
		}
	}
	BitmapEx(const WCHAR* filename)
		: Gdiplus::Bitmap::Bitmap(filename)
		, m_lpByte(0), m_nSize(0) {
		if (GetLastStatus() == Gdiplus::Ok) {
			GUID guid;
			if (GetRawFormat(&guid) == Gdiplus::Ok) {
				if (guid == Gdiplus::ImageFormatGIF) {
					UINT count = GetFrameDimensionsCount();
					GUID* pDimensionIDs = new GUID[count];
					GetFrameDimensionsList(pDimensionIDs, count);
					int nFrameCount = GetFrameCount(&pDimensionIDs[0]);
					delete[]pDimensionIDs;
					if (nFrameCount > 1) {
						HANDLE hFile = CreateFileW(filename, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
						if (hFile != INVALID_HANDLE_VALUE) {
							DWORD dwReadSize;
							m_nSize = GetFileSize(hFile, 0);
							m_lpByte = (LPBYTE)GlobalAlloc(0, m_nSize);
							ReadFile(hFile, m_lpByte, m_nSize, &dwReadSize, 0);
							CloseHandle(hFile);
						}
					}
				}
			}
		}
		else {
			lastResult = Gdiplus::UnknownImageFormat;
		}
	}
	virtual ~BitmapEx() {
		GlobalFree(m_lpByte);
		m_lpByte = 0;
	}
};

Gdiplus::Bitmap* LoadBitmapFromResource(int nID, LPCWSTR lpszType)
{
	Gdiplus::Bitmap* pBitmap = 0;
	const HINSTANCE hInstance = GetModuleHandle(0);
	const HRSRC hResource = FindResourceW(hInstance, MAKEINTRESOURCE(nID), lpszType);
	if (!hResource)
		return 0;
	const DWORD dwImageSize = SizeofResource(hInstance, hResource);
	if (!dwImageSize)
		return 0;
	const void* pResourceData = LockResource(LoadResource(hInstance, hResource));
	if (!pResourceData)
		return 0;
	const HGLOBAL hBuffer = GlobalAlloc(GMEM_MOVEABLE, dwImageSize);
	if (hBuffer) {
		void* pBuffer = GlobalLock(hBuffer);
		if (pBuffer) {
			CopyMemory(pBuffer, pResourceData, dwImageSize);
			IStream* pStream = NULL;
			if (CreateStreamOnHGlobal(hBuffer, TRUE, &pStream) == S_OK) {
				pBitmap = Gdiplus::Bitmap::FromStream(pStream);
				if (pBitmap) {
					if (pBitmap->GetLastStatus() != Gdiplus::Ok) {
						delete pBitmap;
						pBitmap = NULL;
					}
				}
				pStream->Release();
			}
			GlobalUnlock(hBuffer);
		}
	}
	return pBitmap;
}

BitmapEx* WindowCapture(HWND hWnd)
{
	BitmapEx* pBitmap = 0;
	RECT rect1;
	GetWindowRect(hWnd, &rect1);
	RECT rect2;
	if (DwmGetWindowAttribute(hWnd, DWMWA_EXTENDED_FRAME_BOUNDS, &rect2, sizeof(rect2)) != S_OK) rect2 = rect1;
	HDC hdc = GetDC(0);
	HDC hMem = CreateCompatibleDC(hdc);
	HBITMAP hBitmap = CreateCompatibleBitmap(hdc, rect2.right - rect2.left, rect2.bottom - rect2.top);
	if (hBitmap) {
		HBITMAP hOldBitmap = (HBITMAP)SelectObject(hMem, hBitmap);
		SetForegroundWindow(hWnd);
		InvalidateRect(hWnd, 0, 1);
		UpdateWindow(hWnd);
		BitBlt(hMem, 0, 0, rect2.right - rect2.left, rect2.bottom - rect2.top, hdc, rect2.left, rect2.top, SRCCOPY);
		pBitmap = new BitmapEx(hBitmap);
		SelectObject(hMem, hOldBitmap);
		DeleteObject(hBitmap);
	}
	DeleteDC(hMem);
	ReleaseDC(0, hdc);
	return pBitmap;
}

BitmapEx* ScreenCapture(LPRECT lpRect)
{
	BitmapEx* pBitmap = 0;
	HDC hdc = GetDC(0);
	HDC hMem = CreateCompatibleDC(hdc);
	HBITMAP hBitmap = CreateCompatibleBitmap(hdc, lpRect->right - lpRect->left, lpRect->bottom - lpRect->top);
	if (hBitmap) {
		HBITMAP hOldBitmap = (HBITMAP)SelectObject(hMem, hBitmap);
		BitBlt(hMem, 0, 0, lpRect->right - lpRect->left, lpRect->bottom - lpRect->top, hdc, lpRect->left, lpRect->top, SRCCOPY);
		pBitmap = new BitmapEx(hBitmap);
		SelectObject(hMem, hOldBitmap);
		DeleteObject(hBitmap);
	}
	DeleteDC(hMem);
	ReleaseDC(0, hdc);
	return pBitmap;
}

LRESULT CALLBACK LayerWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
	static HWND hParentWnd;
	static BOOL bDrag;
	static BOOL bDown;
	static POINT posStart;
	static RECT OldRect;
	switch (msg) {
	case WM_CREATE:
		hParentWnd = (HWND)((LPCREATESTRUCT)lParam)->lpCreateParams;
		break;
	case WM_KEYDOWN:
	case WM_RBUTTONDOWN:
		SendMessage(hWnd, WM_CLOSE, 0, 0);
		break;
	case WM_LBUTTONDOWN:
	{
		int xPos = GET_X_LPARAM(lParam);
		int yPos = GET_Y_LPARAM(lParam);
		POINT point = { xPos, yPos };
		ClientToScreen(hWnd, &point);
		posStart = point;
		SetCapture(hWnd);
	}
	break;
	case WM_MOUSEMOVE:
		if (GetCapture() == hWnd)
		{
			int xPos = GET_X_LPARAM(lParam);
			int yPos = GET_Y_LPARAM(lParam);
			POINT point = { xPos, yPos };
			ClientToScreen(hWnd, &point);
			if (!bDrag) {
				if (abs(xPos - posStart.x) > GetSystemMetrics(SM_CXDRAG) && abs(yPos - posStart.y) > GetSystemMetrics(SM_CYDRAG)) {
					bDrag = TRUE;
				}
			}
			else {
				HDC hdc = GetDC(hWnd);
				RECT rect = { min(point.x, posStart.x), min(point.y, posStart.y), max(point.x, posStart.x), max(point.y, posStart.y) };
				OffsetRect(&rect, -GetSystemMetrics(SM_XVIRTUALSCREEN), -GetSystemMetrics(SM_YVIRTUALSCREEN));
				HBRUSH hBrush = CreateSolidBrush(RGB(255, 0, 0));
				HRGN hRgn1 = CreateRectRgn(OldRect.left, OldRect.top, OldRect.right, OldRect.bottom);
				HRGN hRgn2 = CreateRectRgn(rect.left, rect.top, rect.right, rect.bottom);
				CombineRgn(hRgn1, hRgn1, hRgn2, RGN_DIFF);
				FillRgn(hdc, hRgn1, (HBRUSH)GetStockObject(BLACK_BRUSH));
				FillRect(hdc, &rect, hBrush);
				OldRect = rect;
				DeleteObject(hBrush);
				DeleteObject(hRgn1);
				DeleteObject(hRgn2);
				ReleaseDC(hWnd, hdc);
			}
		}
		break;
	case WM_LBUTTONUP:
		if (GetCapture() == hWnd) {
			ReleaseCapture();
			Gdiplus::Bitmap* pBitmap = 0;
			if (bDrag) {
				bDrag = FALSE;
				int xPos = GET_X_LPARAM(lParam);
				int yPos = GET_Y_LPARAM(lParam);
				POINT point = { xPos, yPos };
				ClientToScreen(hWnd, &point);
				RECT rect = { min(point.x, posStart.x), min(point.y, posStart.y), max(point.x, posStart.x), max(point.y, posStart.y) };
				ShowWindow(hWnd, SW_HIDE);
				pBitmap = ScreenCapture(&rect);
			}
			else {
				ShowWindow(hWnd, SW_HIDE);
				HWND hTargetWnd = WindowFromPoint(posStart);
				hTargetWnd = GetAncestor(hTargetWnd, GA_ROOT);
				if (hTargetWnd) {
					pBitmap = WindowCapture(hTargetWnd);
				}
			}
			SendMessage(hParentWnd, WM_APP, 0, (LPARAM)pBitmap);
		}
		break;
	default:
		return DefWindowProc(hWnd, msg, wParam, lParam);
	}
	return 0;
}

class ImageListPanel {
	BOOL m_bDrag;
	int m_nDragIndex;
	int m_nSplitPrevIndex;
	int m_nSplitPrevPosX;
	int m_nMargin;
	int m_nImageMaxCount;
	HFONT m_hFont;
	std::list<BitmapEx*> m_listBitmap;
	WNDPROC fnWndProc;
	Gdiplus::Bitmap* m_pCameraIcon;
	BOOL MoveImage(int nIndexFrom, int nIndexTo) {
		if (nIndexFrom < 0) nIndexFrom = 0;
		if (nIndexTo < 0) nIndexTo = 0;
		if (nIndexFrom == nIndexTo) return FALSE;
		std::list<BitmapEx*>::iterator itFrom = m_listBitmap.begin();
		std::list<BitmapEx*>::iterator itTo = m_listBitmap.begin();
		std::advance(itFrom, nIndexFrom);
		std::advance(itTo, nIndexTo);
		m_listBitmap.splice(itTo, m_listBitmap, itFrom);
		return TRUE;
	}
	static LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
		if (msg == WM_NCCREATE) {
			SetWindowLongPtr(hWnd, GWLP_USERDATA, (LONG_PTR)((LPCREATESTRUCT)lParam)->lpCreateParams);
			return TRUE;
		}
		ImageListPanel* _this = (ImageListPanel*)GetWindowLongPtr(hWnd, GWLP_USERDATA);
		if (_this) {
			switch (msg) {
			case WM_DROPFILES:
			{
				HDROP hDrop = (HDROP)wParam;
				WCHAR szFileName[MAX_PATH];
				UINT iFile, nFiles;
				nFiles = DragQueryFile((HDROP)hDrop, 0xFFFFFFFF, NULL, 0);
				BOOL bUpdate = FALSE;
				for (iFile = 0; iFile < nFiles; ++iFile) {
					if ((int)_this->m_listBitmap.size() >= _this->m_nImageMaxCount) break;
					DragQueryFileW(hDrop, iFile, szFileName, _countof(szFileName));
					BitmapEx* pBitmap = new BitmapEx(szFileName);
					if (pBitmap) {
						if (pBitmap->GetLastStatus() == Gdiplus::Ok) {
							_this->m_listBitmap.push_back(pBitmap);
							bUpdate = TRUE;
						}
						else {
							delete pBitmap;
						}
					}
				}
				DragFinish(hDrop);
				if (bUpdate)
					InvalidateRect(hWnd, 0, 1);
			}
			return 0;
			case WM_PAINT:
			{
				PAINTSTRUCT ps;
				HDC hdc = BeginPaint(hWnd, &ps);
				{
					RECT rect;
					GetClientRect(hWnd, &rect);
					INT nLeft = _this->m_nMargin;
					Gdiplus::Graphics g(hdc);
					int nHeight1 = rect.bottom - 2 * _this->m_nMargin;
					Gdiplus::StringFormat f;
					f.SetAlignment(Gdiplus::StringAlignmentCenter);
					f.SetLineAlignment(Gdiplus::StringAlignmentCenter);
					if (_this->m_listBitmap.size() == 0) {
						Gdiplus::Font font(hdc, _this->m_hFont);
						Gdiplus::RectF rectf((Gdiplus::REAL)0, (Gdiplus::REAL)0, (Gdiplus::REAL)rect.right, (Gdiplus::REAL)rect.bottom);
						g.DrawString(L"画像をドロップ または クリックして画像を選択", -1, &font, rectf, &f, &Gdiplus::SolidBrush(Gdiplus::Color::MakeARGB(128, 0, 0, 0)));
					}
					else {
						Gdiplus::Font font(&Gdiplus::FontFamily(L"Marlett"), 11, Gdiplus::FontStyleRegular, Gdiplus::UnitPixel);
						for (auto bitmap : _this->m_listBitmap) {
							int nWidth = bitmap->GetWidth() * nHeight1 / bitmap->GetHeight();
							g.DrawImage(bitmap, nLeft, _this->m_nMargin, nWidth, nHeight1);
							Gdiplus::RectF rectf((Gdiplus::REAL)(nLeft + nWidth - 16), (Gdiplus::REAL)(_this->m_nMargin), (Gdiplus::REAL)(16), (Gdiplus::REAL)(16));
							g.FillRectangle(&Gdiplus::SolidBrush(Gdiplus::Color::MakeARGB(192, 255, 255, 255)), rectf);
							g.DrawString(L"r", 1, &font, rectf, &f, &Gdiplus::SolidBrush(Gdiplus::Color::MakeARGB(192, 0, 0, 0)));
							nLeft += nWidth + _this->m_nMargin;
						}
					}
					int nCameraIconWidth = _this->m_pCameraIcon->GetWidth();
					int nCameraIconHeigth = _this->m_pCameraIcon->GetHeight();
					g.DrawImage(_this->m_pCameraIcon, rect.right - nCameraIconWidth - 2, rect.bottom - nCameraIconHeigth - 2, nCameraIconWidth, nCameraIconHeigth);
				}
				EndPaint(hWnd, &ps);
			}
			return 0;
			case WM_APP:
			{
				BitmapEx* pBitmap = (BitmapEx*)lParam;
				BOOL bPushed = FALSE;
				if ((int)_this->m_listBitmap.size() < _this->m_nImageMaxCount) {
					if (pBitmap) {
						_this->m_listBitmap.push_back(pBitmap);
						InvalidateRect(hWnd, 0, 1);
						bPushed = TRUE;
					}
				}
				if (!bPushed)
					delete pBitmap;
				SetForegroundWindow(hWnd);
			}
			break;
			case WM_LBUTTONDOWN:
			{
				RECT rect;
				GetClientRect(hWnd, &rect);
				POINT point = { LOWORD(lParam), HIWORD(lParam) };
				int nCameraIconWidth = _this->m_pCameraIcon->GetWidth();
				int nCameraIconHeigth = _this->m_pCameraIcon->GetHeight();
				RECT rectCameraIcon = { rect.right - nCameraIconWidth - 2, rect.bottom - nCameraIconHeigth - 2, rect.right, rect.bottom };
				if (PtInRect(&rectCameraIcon, point)) {
					HWND hLayerWnd = CreateWindowExW(WS_EX_LAYERED | WS_EX_TOPMOST, L"LayerWindow", 0, WS_POPUP, 0, 0, 0, 0, 0, 0, GetModuleHandle(0), (LPVOID)hWnd);
					SetLayeredWindowAttributes(hLayerWnd, RGB(255, 0, 0), 64, LWA_ALPHA | LWA_COLORKEY);
					SetWindowPos(hLayerWnd, HWND_TOPMOST, GetSystemMetrics(SM_XVIRTUALSCREEN), GetSystemMetrics(SM_YVIRTUALSCREEN), GetSystemMetrics(SM_CXVIRTUALSCREEN), GetSystemMetrics(SM_CYVIRTUALSCREEN), SWP_NOSENDCHANGING);
					ShowWindow(hLayerWnd, SW_NORMAL);
					UpdateWindow(hLayerWnd);
					return 0;
				}
				INT nLeft = _this->m_nMargin;
				int nHeight1 = rect.bottom - 2 * _this->m_nMargin;
				for (auto it = _this->m_listBitmap.begin(); it != _this->m_listBitmap.end(); ++it) {
					int nWidth1 = (*it)->GetWidth() * nHeight1 / (*it)->GetHeight();
					RECT rectCloseButton = { nLeft + nWidth1 - 16, _this->m_nMargin, nLeft + nWidth1, _this->m_nMargin + 16};
					if (PtInRect(&rectCloseButton, point)) {
						delete* it;
						*it = 0;
						_this->m_listBitmap.erase(it);
						InvalidateRect(hWnd, 0, 1);
						return 0;
					}
					nLeft += nWidth1 + _this->m_nMargin;
				}
				nLeft = _this->m_nMargin;
				int nIndex = 0;
				for (auto it = _this->m_listBitmap.begin(); it != _this->m_listBitmap.end(); ++it) {
					int nWidth1 = (*it)->GetWidth() * nHeight1 / (*it)->GetHeight();
					RECT rectImage = { nLeft, _this->m_nMargin, nLeft + nWidth1, _this->m_nMargin + nWidth1 };
					if (PtInRect(&rectImage, point)) {
						_this->m_bDrag = TRUE;
						SetCapture(hWnd);
						_this->m_nDragIndex = nIndex;
						return 0;
					}
					nLeft += nWidth1 + _this->m_nMargin;
					++nIndex;
				}
				if ((int)_this->m_listBitmap.size() < _this->m_nImageMaxCount) {
					WCHAR szFileName[MAX_PATH] = { 0 };
					OPENFILENAMEW of = { sizeof(OPENFILENAME) };
					WCHAR szMyDocumentFolder[MAX_PATH];
					SHGetFolderPathW(NULL, CSIDL_MYPICTURES, NULL, NULL, szMyDocumentFolder);//
					PathAddBackslashW(szMyDocumentFolder);
					of.hwndOwner = hWnd;
					of.lpstrFilter = L"画像ファイル\0*.png;*.gif;*.jpg;*.jpeg;*.bmp;*.tif;*.ico;*.emf;*.wmf;\0すべてのファイル(*.*)\0*.*\0\0";
					of.lpstrFile = szFileName;
					of.nMaxFile = MAX_PATH;
					of.Flags = OFN_FILEMUSTEXIST | OFN_HIDEREADONLY;
					of.lpstrTitle = L"画像ファイルを開く";
					of.lpstrInitialDir = szMyDocumentFolder;
					if (GetOpenFileNameW(&of)) {
						BitmapEx* pBitmap = new BitmapEx(szFileName);
						if (pBitmap) {
							if (pBitmap->GetLastStatus() == Gdiplus::Ok) {
								_this->m_listBitmap.push_back(pBitmap);
								InvalidateRect(hWnd, 0, 1);
							}
							else {
								delete pBitmap;
							}
						}
					}
				}
			}
			return 0;
			case WM_MOUSEMOVE:
				if (_this->m_bDrag) {
					RECT rect;
					GetClientRect(hWnd, &rect);
					INT nCursorX = LOWORD(lParam);
					INT nLeft = 0;
					int nHeight1 = rect.bottom - 2 * _this->m_nMargin;
					int nIndex = 0;
					for (auto it = _this->m_listBitmap.begin(); it != _this->m_listBitmap.end(); ++it) {
						int nWidth1 = (*it)->GetWidth() * nHeight1 / (*it)->GetHeight();
						RECT rectImage = { nLeft, 0, nLeft + nWidth1 + _this->m_nMargin , rect.bottom};
						if (nCursorX >= nLeft && (nIndex + 1 == _this->m_listBitmap.size() || nCursorX < nLeft + nWidth1 + _this->m_nMargin)) {
							int nCurrentIndex;
							int nCurrentPosX;
							if (nCursorX < nLeft + nWidth1 / 2 + _this->m_nMargin) {
								nCurrentIndex = nIndex;
								nCurrentPosX = nLeft;
							}
							else {
								nCurrentIndex = nIndex + 1;
								nCurrentPosX = nLeft + nWidth1 + _this->m_nMargin;
							}
							if (nCurrentIndex != _this->m_nSplitPrevIndex) {
								HDC hdc = GetDC(hWnd);
								if (_this->m_nSplitPrevIndex != -1)
									PatBlt(hdc, _this->m_nSplitPrevPosX, 0, _this->m_nMargin, rect.bottom, PATINVERT);
								PatBlt(hdc, nCurrentPosX, 0, _this->m_nMargin, rect.bottom, PATINVERT);
								ReleaseDC(hWnd, hdc);
								_this->m_nSplitPrevIndex = nCurrentIndex;
								_this->m_nSplitPrevPosX = nCurrentPosX;
							}
							return 0;
						}
						nLeft += nWidth1 + _this->m_nMargin;
						++nIndex;
					}
				}
				return 0;
			case WM_LBUTTONUP:
				if (_this->m_bDrag) {
					ReleaseCapture();
					_this->m_bDrag = FALSE;
					if (_this->m_nSplitPrevIndex != -1) {
						RECT rect;
						GetClientRect(hWnd, &rect);
						HDC hdc = GetDC(hWnd);
						PatBlt(hdc, _this->m_nSplitPrevPosX, 0, _this->m_nMargin, rect.bottom, PATINVERT);
						ReleaseDC(hWnd, hdc);
						if (_this->MoveImage(_this->m_nDragIndex, _this->m_nSplitPrevIndex)) {
							InvalidateRect(hWnd, 0, 1);
						}
						_this->m_nSplitPrevIndex = -1;
					}
				}
				return 0;
			}
		}
		return DefWindowProc(hWnd, msg, wParam, lParam);
	}
	void RemoveAllImage() {
		for (auto& bitmap : m_listBitmap) {
			delete bitmap;
			bitmap = 0;
		}
		m_listBitmap.clear();
	}
public:
	HWND m_hWnd;
	ImageListPanel(int nImageMaxCount, DWORD dwStyle, int x, int y, int width, int height, HWND hParent, HFONT hFont)
		: m_nImageMaxCount(nImageMaxCount)
		, m_hWnd(0)
		, fnWndProc(0)
		, m_nMargin(4)
		, m_bDrag(0)
		, m_nSplitPrevIndex(-1)
		, m_nSplitPrevPosX(0)
		, m_hFont(hFont)
		, m_pCameraIcon(0) {
		m_pCameraIcon = LoadBitmapFromResource(IDB_PNG1, L"PNG");
		WNDCLASSW wndclass1 = { 0,LayerWndProc,0,0,GetModuleHandle(0),0,LoadCursor(0,IDC_CROSS),(HBRUSH)GetStockObject(BLACK_BRUSH),0,L"LayerWindow" };
		RegisterClassW(&wndclass1);
		WNDCLASSW wndclass2 = { CS_HREDRAW | CS_VREDRAW,WndProc,0,0,GetModuleHandle(0),0,LoadCursor(0,IDC_ARROW),(HBRUSH)(COLOR_WINDOW + 1),0,__FUNCTIONW__ };
		RegisterClassW(&wndclass2);
		m_hWnd = CreateWindowW(__FUNCTIONW__, 0, dwStyle, x, y, width, height, hParent, 0, GetModuleHandle(0), this);
	}
	~ImageListPanel() {
		RemoveAllImage();
		delete m_pCameraIcon;
	}
	int GetImageCount() { return (int)m_listBitmap.size(); }
	BitmapEx* GetImage(int nIndex) {
		std::list<BitmapEx*>::iterator it = m_listBitmap.begin();
		std::advance(it, nIndex);
		return *it;
	}
	void ResetContent() {
		RemoveAllImage();
		InvalidateRect(m_hWnd, 0, 1);
	}
};

BOOL GetEncoderClsid(LPCWSTR format, CLSID* pClsid) {
	UINT  num = 0, size = 0;
	Gdiplus::GetImageEncodersSize(&num, &size);
	if (size == 0) return FALSE;
	Gdiplus::ImageCodecInfo* pImageCodecInfo = (Gdiplus::ImageCodecInfo*)(GlobalAlloc(0, size));
	if (pImageCodecInfo == NULL) return FALSE;
	GetImageEncoders(num, size, pImageCodecInfo);
	for (UINT i = 0; i < num; ++i) {
		if (wcscmp(pImageCodecInfo[i].MimeType, format) == 0) {
			*pClsid = pImageCodecInfo[i].Clsid;
			GlobalFree(pImageCodecInfo);
			return TRUE;
		}
	}
	GlobalFree(pImageCodecInfo);
	return FALSE;
}

LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
	static HWND hEditConsumerKey;
	static HWND hEditConsumerSecret;
	static HWND hEditAccessToken;
	static HWND hEditAccessTokenSecret;
	static HWND hEditMessage;
	static ImageListPanel* pImageListPanel;
	static HWND hButton;
	static HFONT hFont;
	switch (msg)
	{
	case WM_CREATE:
		hFont = CreateFontW(22, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, L"Yu Gothic UI");
		hEditConsumerKey = CreateWindowEx(0, L"EDIT", L"", WS_VISIBLE | WS_CHILD | WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL, 0, 0, 0, 0, hWnd, 0, ((LPCREATESTRUCT)lParam)->hInstance, 0);
		SendMessage(hEditConsumerKey, EM_SETCUEBANNER, TRUE, (LPARAM)L"Consumer Key");
		SendMessage(hEditConsumerKey, WM_SETFONT, (WPARAM)hFont, 0);
		hEditConsumerSecret = CreateWindowEx(0, L"EDIT", L"", WS_VISIBLE | WS_CHILD | WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL, 0, 0, 0, 0, hWnd, 0, ((LPCREATESTRUCT)lParam)->hInstance, 0);
		SendMessage(hEditConsumerSecret, EM_SETCUEBANNER, TRUE, (LPARAM)L"Consumer Secret");
		SendMessage(hEditConsumerSecret, WM_SETFONT, (WPARAM)hFont, 0);
		hEditAccessToken = CreateWindowEx(0, L"EDIT", L"", WS_VISIBLE | WS_CHILD | WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL, 0, 0, 0, 0, hWnd, 0, ((LPCREATESTRUCT)lParam)->hInstance, 0);
		SendMessage(hEditAccessToken, EM_SETCUEBANNER, TRUE, (LPARAM)L"Access Token");
		SendMessage(hEditAccessToken, WM_SETFONT, (WPARAM)hFont, 0);
		hEditAccessTokenSecret = CreateWindowEx(0, L"EDIT", L"", WS_VISIBLE | WS_CHILD | WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL, 0, 0, 0, 0, hWnd, 0, ((LPCREATESTRUCT)lParam)->hInstance, 0);
		SendMessage(hEditAccessTokenSecret, EM_SETCUEBANNER, TRUE, (LPARAM)L"Access Token Secret");
		SendMessage(hEditAccessTokenSecret, WM_SETFONT, (WPARAM)hFont, 0);
		hEditMessage = CreateWindowEx(0, L"EDIT", L"", WS_VISIBLE | WS_CHILD | WS_BORDER | WS_TABSTOP | ES_MULTILINE | ES_AUTOHSCROLL | ES_AUTOVSCROLL, 0, 0, 0, 0, hWnd, 0, ((LPCREATESTRUCT)lParam)->hInstance, 0);
		SendMessage(hEditMessage, WM_SETFONT, (WPARAM)hFont, 0);
		pImageListPanel = new ImageListPanel(4, WS_VISIBLE | WS_CHILD | WS_BORDER, 0, 0, 0, 0, hWnd, hFont);
		hButton = CreateWindow(L"BUTTON", L"ポスト", WS_VISIBLE | WS_CHILD | WS_TABSTOP, 0, 0, 0, 0, hWnd, (HMENU)IDOK, ((LPCREATESTRUCT)lParam)->hInstance, 0);
		SendMessage(hButton, WM_SETFONT, (WPARAM)hFont, 0);
		DragAcceptFiles(hWnd, TRUE);
		break;

	case WM_DROPFILES:
		if (pImageListPanel) {
			SendMessageW(pImageListPanel->m_hWnd, msg, wParam, lParam);
		}
		break;
	case WM_SIZE:
		MoveWindow(hEditConsumerKey, 10, 10, 512, 32, TRUE);
		MoveWindow(hEditConsumerSecret, 10, 50, 512, 32, TRUE);
		MoveWindow(hEditAccessToken, 10, 90, 512, 32, TRUE);
		MoveWindow(hEditAccessTokenSecret, 10, 130, 512, 32, TRUE);
		MoveWindow(hEditMessage, 10, 170, 512, 256 - 64 - 8, TRUE);
		MoveWindow(pImageListPanel->m_hWnd, 10, 170 + 256 - 64 - 8 + 8, 512, 64, TRUE);
		MoveWindow(hButton, 10, 238 + 256 - 64 - 8 + 11, 512, 32, TRUE);
		break;
	case WM_COMMAND:
		if (LOWORD(wParam) == IDOK) {
			CHAR szConsumerKey[256];
			CHAR szConsumerSecret[256];
			CHAR szAccessTokenKey[256];
			CHAR szAccessTokenSecret[256];

			GetWindowTextA(hEditConsumerKey, szConsumerKey, _countof(szConsumerKey));
			GetWindowTextA(hEditConsumerSecret, szConsumerSecret, _countof(szConsumerSecret));
			GetWindowTextA(hEditAccessToken, szAccessTokenKey, _countof(szAccessTokenKey));
			GetWindowTextA(hEditAccessTokenSecret, szAccessTokenSecret, _countof(szAccessTokenSecret));

			std::map<std::string, std::string> m;

			std::vector<std::string> media_ids;

			int nImageCount = pImageListPanel->GetImageCount();

			if (nImageCount > 0) {
				m.clear();
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

				LPSTR lpszOAuthParam = CreateOAuthPram(m, "https://upload.twitter.com/1.1/media/upload.json", szConsumerSecret, szAccessTokenSecret, TRUE);

				if (lpszOAuthParam) {
					for (int i = 0; i < nImageCount; ++i) {
						BitmapEx* pImage = pImageListPanel->GetImage(i);
						GUID guid1;
						LPWSTR lpszMediaType;
						if (pImage->GetRawFormat(&guid1) != Gdiplus::Ok) continue;
						if (guid1 == Gdiplus::ImageFormatGIF && pImage->m_lpByte) {
							lpszMediaType = L"image/gif";
						}
						else if (guid1 == Gdiplus::ImageFormatJPEG || guid1 == Gdiplus::ImageFormatEXIF) {
							lpszMediaType = L"image/jpeg";
						}
						else {
							lpszMediaType = L"image/png";
						}
						GUID guid2;
						GetEncoderClsid(lpszMediaType, &guid2);

						std::string media_id;

						if (pImage->m_lpByte) {
							media_id = image_upload(hWnd, lpszOAuthParam, pImage->m_lpByte);
						}
						else {
							IStream* pStream = NULL;
							if (CreateStreamOnHGlobal(NULL, TRUE, &pStream) == S_OK) {
								if (pImage->Save(pStream, &guid2) == S_OK) {
									ULARGE_INTEGER ulnSize;
									LARGE_INTEGER lnOffset;
									lnOffset.QuadPart = 0;
									if (pStream->Seek(lnOffset, STREAM_SEEK_END, &ulnSize) == S_OK) {
										if (pStream->Seek(lnOffset, STREAM_SEEK_SET, NULL) == S_OK) {
											LPBYTE baPicture = (LPBYTE)GlobalAlloc(0, (SIZE_T)ulnSize.QuadPart);
											ULONG ulBytesRead;
											pStream->Read(baPicture, (ULONG)ulnSize.QuadPart, &ulBytesRead);
											media_id = image_upload(hWnd, lpszOAuthParam, baPicture);
											GlobalFree(baPicture);
										}
									}
								}
								pStream->Release();
							}
						}
						if (!media_id.empty()) {
							media_ids.push_back(media_id);
						}
						else {
							WCHAR szText[512];
							wsprintf(szText, TEXT("投稿に失敗しました。\r\n%d 番目の添付メディアのアップロードに失敗しました。"), i + 1);
							MessageBoxW(hWnd, szText, L"確認", MB_ICONHAND);
							GlobalFree(lpszOAuthParam);
							return 0;
						}
					}
					GlobalFree(lpszOAuthParam);
				}
			}

			m.clear();
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

			LPSTR lpszOAuthParam = CreateOAuthPram(m, "https://api.twitter.com/2/tweets", szConsumerSecret, szAccessTokenSecret, TRUE);
			if (lpszOAuthParam) {
				std::string id;
				DWORD size = GetWindowTextLength(hEditMessage);
				LPWSTR lpszMessageW = (LPWSTR)GlobalAlloc(0, sizeof(WCHAR) * (size + 1));
				if (lpszMessageW) {
					GetWindowText(hEditMessage, lpszMessageW, size + 1);
					size = WideCharToMultiByte(CP_UTF8, 0, lpszMessageW, -1, 0, 0, 0, 0);
					LPSTR lpszMessageA = (LPSTR)GlobalAlloc(GPTR, size);
					if (lpszMessageA) {
						WideCharToMultiByte(CP_UTF8, 0, lpszMessageW, -1, lpszMessageA, size, 0, 0);
						id = tweet(hWnd, lpszOAuthParam, lpszMessageA, media_ids);
						GlobalFree(lpszMessageA);
					}
					GlobalFree(lpszMessageW);
				}

				if (!id.empty())
				{
					std::string message;
					message = "ポストされました(id:";
					message += id;
					message += ")";
					MessageBoxA(hWnd, message.c_str(), "成功", MB_OK);
				}

				GlobalFree(lpszOAuthParam);
			}
		}
		break;
	case WM_CLOSE:
		DestroyWindow(hWnd);
		break;
	case WM_DESTROY:
		delete pImageListPanel;
		DeleteObject(hFont);
		PostQuitMessage(0);
		break;
	default:
		return DefDlgProc(hWnd, msg, wParam, lParam);
	}
	return 0;
}

int WINAPI wWinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance, _In_ LPWSTR lpCmdLine, _In_ int nShowCmd)
{
	ULONG_PTR gdiToken;
	GdiplusStartupInput gdiSI;
	GdiplusStartup(&gdiToken, &gdiSI, NULL);

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

	RECT rect = { 0,0,532,475 };
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
	GdiplusShutdown(gdiToken);
	return (int)msg.wParam;
}
