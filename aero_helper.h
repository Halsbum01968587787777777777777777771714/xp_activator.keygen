#ifndef AERO_HELPER_H
#define AERO_HELPER_H

#include <windows.h>

// Struktur für den Accent-Policy-Hack (undokumentiert)
typedef struct {
    int AccentState;
    int AccentFlags;
    int GradientColor;
    int AnimationId;
} ACCENTPOLICY;

typedef struct {
    int AccentState;
    ACCENTPOLICY *pAccentPolicy;
    int PolicySize;
} WINDOWCOMPOSITIONATTRIBDATA;

static void EnableAeroGlass(HWND hDlg) {
    HMODULE hUser = LoadLibraryW(L"user32.dll");
    if (hUser) {
        typedef BOOL (WINAPI *pSetWindowCompositionAttribute)(HWND, WINDOWCOMPOSITIONATTRIBDATA*);
        pSetWindowCompositionAttribute SetWindowCompositionAttribute = 
            (pSetWindowCompositionAttribute)GetProcAddress(hUser, "SetWindowCompositionAttribute");

        if (SetWindowCompositionAttribute) {
            ACCENTPOLICY policy = {3, 0, 0, 0}; // 3 = ACCENT_ENABLE_BLURBEHIND
            WINDOWCOMPOSITIONATTRIBDATA data = {19, &policy, sizeof(ACCENTPOLICY)}; // 19 = WCA_ACCENT_POLICY
            SetWindowCompositionAttribute(hDlg, &data);
        }
        FreeLibrary(hUser);
    }
}

#endif