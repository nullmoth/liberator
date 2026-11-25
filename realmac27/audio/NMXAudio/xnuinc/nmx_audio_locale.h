/* Original NMXAudio localization helper. No AppleHDA or SimpleHDA strings/code. */
#ifndef NMX_AUDIO_LOCALE_H
#define NMX_AUDIO_LOCALE_H

#include <stddef.h>
#if defined(KERNEL)
#include <libkern/libkern.h>
#else
#include <string.h>
#endif

typedef enum NMXAudioLocaleCode {
    NMX_AUDIO_LOCALE_EN = 0,
    NMX_AUDIO_LOCALE_ZH_CN,
    NMX_AUDIO_LOCALE_ZH_TW,
    NMX_AUDIO_LOCALE_JA,
    NMX_AUDIO_LOCALE_KO,
    NMX_AUDIO_LOCALE_FR,
    NMX_AUDIO_LOCALE_DE,
    NMX_AUDIO_LOCALE_ES
} NMXAudioLocaleCode;

#define NMX_AUDIO_TEXT_DISPLAY_AUDIO  "display_audio"
#define NMX_AUDIO_TEXT_INTERNAL_SPEAKER "internal_speaker"
#define NMX_AUDIO_TEXT_HEADPHONES "headphones"
#define NMX_AUDIO_TEXT_LINE_OUT "line_out"
#define NMX_AUDIO_TEXT_DIGITAL_OUT "digital_out"
#define NMX_AUDIO_TEXT_MICROPHONE "microphone"
#define NMX_AUDIO_TEXT_LINE_IN "line_in"
#define NMX_AUDIO_TEXT_LEFT "left"
#define NMX_AUDIO_TEXT_RIGHT "right"
#define NMX_AUDIO_TEXT_REAR_ANALOG "rear_analog"
#define NMX_AUDIO_TEXT_FRONT_ANALOG "front_analog"
#define NMX_AUDIO_TEXT_PIN_ROLE_CD "pin_role_cd"
#define NMX_AUDIO_TEXT_PIN_ROLE_SPDIF_OUT "pin_role_spdif_out"
#define NMX_AUDIO_TEXT_PIN_ROLE_DIGITAL_OUT "pin_role_digital_out"
#define NMX_AUDIO_TEXT_PIN_ROLE_MODEM_LINE "pin_role_modem_line"
#define NMX_AUDIO_TEXT_PIN_ROLE_MODEM_HANDSET "pin_role_modem_handset"
#define NMX_AUDIO_TEXT_PIN_ROLE_AUX "pin_role_aux"
#define NMX_AUDIO_TEXT_PIN_ROLE_TELEPHONY "pin_role_telephony"
#define NMX_AUDIO_TEXT_PIN_ROLE_SPDIF_IN "pin_role_spdif_in"
#define NMX_AUDIO_TEXT_PIN_ROLE_DIGITAL_IN "pin_role_digital_in"
#define NMX_AUDIO_TEXT_PIN_ROLE_OTHER "pin_role_other"
#define NMX_AUDIO_TEXT_PIN_LOCATION_REAR "pin_location_rear"
#define NMX_AUDIO_TEXT_PIN_LOCATION_FRONT "pin_location_front"
#define NMX_AUDIO_TEXT_PIN_LOCATION_LEFT "pin_location_left"
#define NMX_AUDIO_TEXT_PIN_LOCATION_RIGHT "pin_location_right"
#define NMX_AUDIO_TEXT_PIN_LOCATION_TOP "pin_location_top"
#define NMX_AUDIO_TEXT_PIN_LOCATION_BOTTOM "pin_location_bottom"
#define NMX_AUDIO_TEXT_PIN_LOCATION_REAR_PANEL "pin_location_rear_panel"
#define NMX_AUDIO_TEXT_PIN_LOCATION_DRIVE_BAY "pin_location_drive_bay"
#define NMX_AUDIO_TEXT_PIN_LOCATION_INTERNAL "pin_location_internal"
#define NMX_AUDIO_TEXT_PIN_LOCATION_RISER "pin_location_riser"
#define NMX_AUDIO_TEXT_PIN_LOCATION_ONBOARD "pin_location_onboard"
#define NMX_AUDIO_TEXT_PIN_LOCATION_EXTERNAL "pin_location_external"
#define NMX_AUDIO_TEXT_PIN_LOCATION_EXT_REAR "pin_location_ext_rear"
#define NMX_AUDIO_TEXT_PIN_LOCATION_EXT_FRONT "pin_location_ext_front"
#define NMX_AUDIO_TEXT_PIN_LOCATION_EXT_LEFT "pin_location_ext_left"
#define NMX_AUDIO_TEXT_PIN_LOCATION_EXT_RIGHT "pin_location_ext_right"
#define NMX_AUDIO_TEXT_PIN_LOCATION_EXT_TOP "pin_location_ext_top"
#define NMX_AUDIO_TEXT_PIN_LOCATION_EXT_BOTTOM "pin_location_ext_bottom"
#define NMX_AUDIO_TEXT_PIN_LOCATION_OTHER "pin_location_other"
#define NMX_AUDIO_TEXT_PIN_LOCATION_OTHER_BOTTOM "pin_location_other_bottom"
#define NMX_AUDIO_TEXT_PIN_LOCATION_LID_IN "pin_location_lid_in"
#define NMX_AUDIO_TEXT_PIN_LOCATION_LID_OUT "pin_location_lid_out"
#define NMX_AUDIO_TEXT_PIN_SIGNAL_ANALOG "pin_signal_analog"
#define NMX_AUDIO_TEXT_PIN_SIGNAL_DIGITAL "pin_signal_digital"
#define NMX_AUDIO_TEXT_PIN_SIGNAL_HDMI "pin_signal_hdmi"
#define NMX_AUDIO_TEXT_PIN_SIGNAL_DISPLAYPORT "pin_signal_displayport"
#define NMX_AUDIO_TEXT_PIN_SIGNAL_HDMI_DP "pin_signal_hdmi_dp"
#define NMX_AUDIO_TEXT_PIN_DIRECTION_INPUT "pin_direction_input"
#define NMX_AUDIO_TEXT_PIN_DIRECTION_OUTPUT "pin_direction_output"
#define NMX_AUDIO_TEXT_PIN_COLOR_BLACK "pin_color_black"
#define NMX_AUDIO_TEXT_PIN_COLOR_GRAY "pin_color_gray"
#define NMX_AUDIO_TEXT_PIN_COLOR_BLUE "pin_color_blue"
#define NMX_AUDIO_TEXT_PIN_COLOR_GREEN "pin_color_green"
#define NMX_AUDIO_TEXT_PIN_COLOR_RED "pin_color_red"
#define NMX_AUDIO_TEXT_PIN_COLOR_ORANGE "pin_color_orange"
#define NMX_AUDIO_TEXT_PIN_COLOR_YELLOW "pin_color_yellow"
#define NMX_AUDIO_TEXT_PIN_COLOR_PURPLE "pin_color_purple"
#define NMX_AUDIO_TEXT_PIN_COLOR_PINK "pin_color_pink"
#define NMX_AUDIO_TEXT_PIN_COLOR_WHITE "pin_color_white"
#define NMX_AUDIO_TEXT_NAME_OPEN "name_open"
#define NMX_AUDIO_TEXT_NAME_CLOSE "name_close"
#define NMX_AUDIO_TEXT_NAME_SEPARATOR "name_separator"
#define NMX_AUDIO_TEXT_NAME_WORD_SEPARATOR "name_word_separator"

/* Accepts locale strings such as "en-US:0" from prev-lang:kbd. */
static inline NMXAudioLocaleCode nmxAudioLocale(const char *locale) {
    char tag[64];
    size_t used = 0;
    const char *p = locale;
    if (!p) return NMX_AUDIO_LOCALE_EN;
    while (*p && *p != ':') {
        unsigned char c = (unsigned char)*p++;
        if (used + 1 >= sizeof(tag)) return NMX_AUDIO_LOCALE_EN;
        if (c == '-') c = '_';
        if (c >= 'A' && c <= 'Z') c = (unsigned char)(c + ('a' - 'A'));
        tag[used++] = (char)c;
    }
    tag[used] = '\0';
    if (used == 0) return NMX_AUDIO_LOCALE_EN;

    if (tag[0] == 'z' && tag[1] == 'h' && (tag[2] == '_' || tag[2] == '\0')) {
        const char *part = tag + (tag[2] == '_' ? 3 : 2);
        while (*part) {
            const char *end = part;
            size_t len;
            while (*end && *end != '_') ++end;
            len = (size_t)(end - part);
            if ((len == 4 && memcmp(part, "hant", 4) == 0) ||
                (len == 2 && (memcmp(part, "tw", 2) == 0 || memcmp(part, "hk", 2) == 0 || memcmp(part, "mo", 2) == 0)))
                return NMX_AUDIO_LOCALE_ZH_TW;
            if ((len == 4 && memcmp(part, "hans", 4) == 0) ||
                (len == 2 && (memcmp(part, "cn", 2) == 0 || memcmp(part, "sg", 2) == 0)))
                return NMX_AUDIO_LOCALE_ZH_CN;
            part = *end ? end + 1 : end;
        }
        return NMX_AUDIO_LOCALE_ZH_CN;
    }

    if (tag[0] == 'e' && tag[1] == 'n' && (tag[2] == '_' || tag[2] == '\0')) return NMX_AUDIO_LOCALE_EN;
    if (tag[0] == 'j' && tag[1] == 'a' && (tag[2] == '_' || tag[2] == '\0')) return NMX_AUDIO_LOCALE_JA;
    if (tag[0] == 'k' && tag[1] == 'o' && (tag[2] == '_' || tag[2] == '\0')) return NMX_AUDIO_LOCALE_KO;
    if (tag[0] == 'f' && tag[1] == 'r' && (tag[2] == '_' || tag[2] == '\0')) return NMX_AUDIO_LOCALE_FR;
    if (tag[0] == 'd' && tag[1] == 'e' && (tag[2] == '_' || tag[2] == '\0')) return NMX_AUDIO_LOCALE_DE;
    if (tag[0] == 'e' && tag[1] == 's' && (tag[2] == '_' || tag[2] == '\0')) return NMX_AUDIO_LOCALE_ES;
    return NMX_AUDIO_LOCALE_EN;
}

static inline const char *nmxAudioText(NMXAudioLocaleCode locale, const char *key) {
    typedef struct NMXAudioLocaleEntry {
        const char *key;
        const char *text[8];
    } NMXAudioLocaleEntry;
    static const NMXAudioLocaleEntry entries[] = {
        { NMX_AUDIO_TEXT_DISPLAY_AUDIO, { "Display Audio", "显示器音频", "顯示器音訊", "ディスプレイオーディオ", "디스플레이 오디오", "Audio de l’écran", "Bildschirm-Audio", "Audio de pantalla" } },
        { NMX_AUDIO_TEXT_INTERNAL_SPEAKER, { "Internal Speaker", "内置扬声器", "內置揚聲器", "内蔵スピーカー", "내장 스피커", "Haut-parleur interne", "Interner Lautsprecher", "Altavoz interno" } },
        { NMX_AUDIO_TEXT_HEADPHONES, { "Headphones", "耳机", "耳機", "ヘッドフォン", "헤드폰", "Écouteurs", "Kopfhörer", "Auriculares" } },
        { NMX_AUDIO_TEXT_LINE_OUT, { "Line Out", "线路输出", "線路輸出", "ライン出力", "라인 출력", "Sortie ligne", "Line-Ausgang", "Salida de línea" } },
        { NMX_AUDIO_TEXT_DIGITAL_OUT, { "Digital Out", "数字输出", "數位輸出", "デジタル出力", "디지털 출력", "Sortie numérique", "Digitalausgang", "Salida digital" } },
        { NMX_AUDIO_TEXT_MICROPHONE, { "Microphone", "麦克风", "麥克風", "マイク", "마이크", "Microphone", "Mikrofon", "Micrófono" } },
        { NMX_AUDIO_TEXT_LINE_IN, { "Line In", "线路输入", "線路輸入", "ライン入力", "라인 입력", "Entrée ligne", "Line-Eingang", "Entrada de línea" } },
        { NMX_AUDIO_TEXT_LEFT, { "Left", "左", "左", "左", "왼쪽", "Gauche", "Links", "Izquierda" } },
        { NMX_AUDIO_TEXT_RIGHT, { "Right", "右", "右", "右", "오른쪽", "Droite", "Rechts", "Derecha" } },
        { NMX_AUDIO_TEXT_REAR_ANALOG, { "Rear Analog", "后置模拟", "後置類比", "リアアナログ", "후면 아날로그", "Analogique arrière", "Analog hinten", "Analógico trasero" } },
        { NMX_AUDIO_TEXT_FRONT_ANALOG, { "Front Analog", "前置模拟", "前置類比", "フロントアナログ", "전면 아날로그", "Analogique avant", "Analog vorn", "Analógico delantero" } },
        { "speaker", { "Speaker", "扬声器", "揚聲器", "スピーカー", "스피커", "Haut-parleur", "Lautsprecher", "Altavoz" } },
        { NMX_AUDIO_TEXT_PIN_ROLE_CD, { "CD", "CD", "CD", "CD", "CD", "CD", "CD", "CD" } },
        { NMX_AUDIO_TEXT_PIN_ROLE_SPDIF_OUT, { "S/PDIF Out", "S/PDIF 输出", "S/PDIF 輸出", "S/PDIF出力", "S/PDIF 출력", "Sortie S/PDIF", "S/PDIF-Ausgang", "Salida S/PDIF" } },
        { NMX_AUDIO_TEXT_PIN_ROLE_DIGITAL_OUT, { "Digital Out", "数字输出", "數位輸出", "デジタル出力", "디지털 출력", "Sortie numérique", "Digitalausgang", "Salida digital" } },
        { NMX_AUDIO_TEXT_PIN_ROLE_MODEM_LINE, { "Modem Line", "调制解调器线路", "數據機線路", "モデム回線", "모뎀 회선", "Ligne modem", "Modemleitung", "Línea de módem" } },
        { NMX_AUDIO_TEXT_PIN_ROLE_MODEM_HANDSET, { "Modem Handset", "调制解调器听筒", "數據機話筒", "モデム受話器", "모뎀 송수화기", "Combiné modem", "Modemhörer", "Auricular de módem" } },
        { NMX_AUDIO_TEXT_PIN_ROLE_AUX, { "Auxiliary", "辅助", "輔助", "補助", "보조", "Auxiliaire", "Zusatz", "Auxiliar" } },
        { NMX_AUDIO_TEXT_PIN_ROLE_TELEPHONY, { "Telephony", "电话音频", "電話音訊", "テレフォニー", "전화 오디오", "Téléphonie", "Telefonie", "Telefonía" } },
        { NMX_AUDIO_TEXT_PIN_ROLE_SPDIF_IN, { "S/PDIF In", "S/PDIF 输入", "S/PDIF 輸入", "S/PDIF入力", "S/PDIF 입력", "Entrée S/PDIF", "S/PDIF-Eingang", "Entrada S/PDIF" } },
        { NMX_AUDIO_TEXT_PIN_ROLE_DIGITAL_IN, { "Digital In", "数字输入", "數位輸入", "デジタル入力", "디지털 입력", "Entrée numérique", "Digitaleingang", "Entrada digital" } },
        { NMX_AUDIO_TEXT_PIN_ROLE_OTHER, { "Other", "其他", "其他", "その他", "기타", "Autre", "Sonstiges", "Otro" } },
        { NMX_AUDIO_TEXT_PIN_LOCATION_REAR, { "Rear", "后置", "後置", "リア", "후면", "Arrière", "Hinten", "Trasero" } },
        { NMX_AUDIO_TEXT_PIN_LOCATION_FRONT, { "Front", "前置", "前置", "フロント", "전면", "Avant", "Vorn", "Delantero" } },
        { NMX_AUDIO_TEXT_PIN_LOCATION_LEFT, { "Left", "左侧", "左側", "左", "왼쪽", "Gauche", "Links", "Izquierdo" } },
        { NMX_AUDIO_TEXT_PIN_LOCATION_RIGHT, { "Right", "右侧", "右側", "右", "오른쪽", "Droite", "Rechts", "Derecho" } },
        { NMX_AUDIO_TEXT_PIN_LOCATION_TOP, { "Top", "顶部", "頂部", "上部", "위쪽", "Haut", "Oben", "Superior" } },
        { NMX_AUDIO_TEXT_PIN_LOCATION_BOTTOM, { "Bottom", "底部", "底部", "下部", "아래쪽", "Bas", "Unten", "Inferior" } },
        { NMX_AUDIO_TEXT_PIN_LOCATION_REAR_PANEL, { "Rear Panel", "后面板", "後面板", "背面パネル", "후면 패널", "Panneau arrière", "Rückseite", "Panel trasero" } },
        { NMX_AUDIO_TEXT_PIN_LOCATION_DRIVE_BAY, { "Drive Bay", "驱动器托架", "磁碟機槽", "ドライブベイ", "드라이브 베이", "Baie de lecteur", "Laufwerksschacht", "Bahía de unidad" } },
        { NMX_AUDIO_TEXT_PIN_LOCATION_INTERNAL, { "Internal", "内部", "內部", "内部", "내부", "Interne", "Intern", "Interno" } },
        { NMX_AUDIO_TEXT_PIN_LOCATION_RISER, { "Riser", "转接卡", "轉接卡", "ライザー", "라이저", "Carte riser", "Riser", "Elevador" } },
        { NMX_AUDIO_TEXT_PIN_LOCATION_ONBOARD, { "Onboard", "板载", "板載", "オンボード", "온보드", "Intégré", "Onboard", "Integrado" } },
        { NMX_AUDIO_TEXT_PIN_LOCATION_EXTERNAL, { "External", "外接", "外接", "外部", "외부", "Externe", "Extern", "Externo" } },
        { NMX_AUDIO_TEXT_PIN_LOCATION_EXT_REAR, { "External Rear", "外接后置", "外接後置", "外部リア", "외부 후면", "Arrière externe", "Extern hinten", "Trasero externo" } },
        { NMX_AUDIO_TEXT_PIN_LOCATION_EXT_FRONT, { "External Front", "外接前置", "外接前置", "外部フロント", "외부 전면", "Avant externe", "Extern vorn", "Delantero externo" } },
        { NMX_AUDIO_TEXT_PIN_LOCATION_EXT_LEFT, { "External Left", "外接左侧", "外接左側", "外部左", "외부 왼쪽", "Gauche externe", "Extern links", "Izquierdo externo" } },
        { NMX_AUDIO_TEXT_PIN_LOCATION_EXT_RIGHT, { "External Right", "外接右侧", "外接右側", "外部右", "외부 오른쪽", "Droite externe", "Extern rechts", "Derecho externo" } },
        { NMX_AUDIO_TEXT_PIN_LOCATION_EXT_TOP, { "External Top", "外接顶部", "外接頂部", "外部上部", "외부 위쪽", "Haut externe", "Extern oben", "Superior externo" } },
        { NMX_AUDIO_TEXT_PIN_LOCATION_EXT_BOTTOM, { "External Bottom", "外接底部", "外接底部", "外部下部", "외부 아래쪽", "Bas externe", "Extern unten", "Inferior externo" } },
        { NMX_AUDIO_TEXT_PIN_LOCATION_OTHER, { "Other", "其他位置", "其他位置", "その他の位置", "기타 위치", "Autre emplacement", "Anderer Ort", "Otra ubicación" } },
        { NMX_AUDIO_TEXT_PIN_LOCATION_OTHER_BOTTOM, { "Other Bottom", "其他底部位置", "其他底部位置", "その他の下部", "기타 아래쪽", "Autre bas", "Anderer unterer Ort", "Otra ubicación inferior" } },
        { NMX_AUDIO_TEXT_PIN_LOCATION_LID_IN, { "Lid In", "机盖内侧", "機蓋內側", "蓋の内側", "덮개 안쪽", "Intérieur du capot", "Deckel innen", "Interior de tapa" } },
        { NMX_AUDIO_TEXT_PIN_LOCATION_LID_OUT, { "Lid Out", "机盖外侧", "機蓋外側", "蓋の外側", "덮개 바깥쪽", "Extérieur du capot", "Deckel außen", "Exterior de tapa" } },
        { NMX_AUDIO_TEXT_PIN_SIGNAL_ANALOG, { "Analog", "模拟", "類比", "アナログ", "아날로그", "Analogique", "Analog", "Analógico" } },
        { NMX_AUDIO_TEXT_PIN_SIGNAL_DIGITAL, { "Digital", "数字", "數位", "デジタル", "디지털", "Numérique", "Digital", "Digital" } },
        { NMX_AUDIO_TEXT_PIN_SIGNAL_HDMI, { "HDMI", "HDMI", "HDMI", "HDMI", "HDMI", "HDMI", "HDMI", "HDMI" } },
        { NMX_AUDIO_TEXT_PIN_SIGNAL_DISPLAYPORT, { "DisplayPort", "DisplayPort", "DisplayPort", "DisplayPort", "DisplayPort", "DisplayPort", "DisplayPort", "DisplayPort" } },
        { NMX_AUDIO_TEXT_PIN_SIGNAL_HDMI_DP, { "HDMI/DisplayPort", "HDMI/DisplayPort", "HDMI/DisplayPort", "HDMI/DisplayPort", "HDMI/DisplayPort", "HDMI/DisplayPort", "HDMI/DisplayPort", "HDMI/DisplayPort" } },
        { NMX_AUDIO_TEXT_PIN_DIRECTION_INPUT, { "Input", "输入", "輸入", "入力", "입력", "Entrée", "Eingang", "Entrada" } },
        { NMX_AUDIO_TEXT_PIN_DIRECTION_OUTPUT, { "Output", "输出", "輸出", "出力", "출력", "Sortie", "Ausgang", "Salida" } },
        { NMX_AUDIO_TEXT_PIN_COLOR_BLACK, { "Black", "黑色", "黑色", "黒", "검정", "Noir", "Schwarz", "Negro" } },
        { NMX_AUDIO_TEXT_PIN_COLOR_GRAY, { "Gray", "灰色", "灰色", "灰色", "회색", "Gris", "Grau", "Gris" } },
        { NMX_AUDIO_TEXT_PIN_COLOR_BLUE, { "Blue", "蓝色", "藍色", "青", "파랑", "Bleu", "Blau", "Azul" } },
        { NMX_AUDIO_TEXT_PIN_COLOR_GREEN, { "Green", "绿色", "綠色", "緑", "녹색", "Vert", "Grün", "Verde" } },
        { NMX_AUDIO_TEXT_PIN_COLOR_RED, { "Red", "红色", "紅色", "赤", "빨강", "Rouge", "Rot", "Rojo" } },
        { NMX_AUDIO_TEXT_PIN_COLOR_ORANGE, { "Orange", "橙色", "橙色", "オレンジ", "주황", "Orange", "Orange", "Naranja" } },
        { NMX_AUDIO_TEXT_PIN_COLOR_YELLOW, { "Yellow", "黄色", "黃色", "黄色", "노랑", "Jaune", "Gelb", "Amarillo" } },
        { NMX_AUDIO_TEXT_PIN_COLOR_PURPLE, { "Purple", "紫色", "紫色", "紫", "보라", "Violet", "Lila", "Morado" } },
        { NMX_AUDIO_TEXT_PIN_COLOR_PINK, { "Pink", "粉色", "粉紅色", "ピンク", "분홍", "Rose", "Rosa", "Rosa" } },
        { NMX_AUDIO_TEXT_PIN_COLOR_WHITE, { "White", "白色", "白色", "白", "흰색", "Blanc", "Weiß", "Blanco" } },
        { NMX_AUDIO_TEXT_NAME_OPEN, { " (", "（", "（", "（", "（", " (", " (", " (" } },
        { NMX_AUDIO_TEXT_NAME_CLOSE, { ")", "）", "）", "）", "）", ")", ")", ")" } },
        { NMX_AUDIO_TEXT_NAME_SEPARATOR, { ", ", "，", "，", "、", ", ", ", ", ", ", ", " } },
        { NMX_AUDIO_TEXT_NAME_WORD_SEPARATOR, { " ", "", "", "", "", " ", " ", " " } }
    };
    size_t i;
    if (!key) return (const char *)0;
    if ((unsigned)locale >= 8U) locale = NMX_AUDIO_LOCALE_EN;
    for (i = 0; i < sizeof(entries) / sizeof(entries[0]); ++i)
        if (strcmp(key, entries[i].key) == 0) return entries[i].text[(unsigned)locale];
    return key;
}

static inline int nmxAudioAppend(char *out, size_t capacity, size_t *used, const char *text)
{
    size_t length;
    if (!out || !used || !text || capacity == 0 || *used >= capacity)
        return 0;
    length = strlen(text);
    if (length >= capacity - *used)
        return 0;
    memcpy(out + *used, text, length);
    *used += length;
    out[*used] = '\0';
    return 1;
}

static inline int nmxAudioFormatPortName(NMXAudioLocaleCode locale,
    const char *location, const char *endpoint, const char *direction,
    char *out, size_t capacity)
{
    const char *parts[3] = { location, endpoint, direction };
    const char *word_separator = nmxAudioText(locale, NMX_AUDIO_TEXT_NAME_WORD_SEPARATOR);
    size_t used = 0;
    int count = 0;
    if (!out || capacity == 0)
        return 0;
    out[0] = '\0';
    for (size_t i = 0; i < sizeof(parts) / sizeof(parts[0]); ++i) {
        if (!parts[i] || !parts[i][0])
            continue;
        if (count && !nmxAudioAppend(out, capacity, &used, word_separator))
            goto fail;
        if (!nmxAudioAppend(out, capacity, &used, parts[i]))
            goto fail;
        ++count;
    }
    return count != 0;
fail:
    out[0] = '\0';
    return 0;
}

static inline int nmxAudioFormatPCMName(NMXAudioLocaleCode locale,
    const char *codec, const char *port, const char *color, const char *channels,
    char *out, size_t capacity)
{
    const char *parts[3] = { port, color, channels };
    size_t used = 0;
    int count = 0;
    int has_codec = codec && codec[0];
    if (!out || capacity == 0)
        return 0;
    out[0] = '\0';
    if (!has_codec && (!port || !port[0]) && (!color || !color[0]) &&
        (!channels || !channels[0]))
        return 0;
    if (has_codec && !nmxAudioAppend(out, capacity, &used, codec))
        goto fail;
    if (has_codec && (port || color || channels) &&
        !nmxAudioAppend(out, capacity, &used, nmxAudioText(locale, NMX_AUDIO_TEXT_NAME_OPEN)))
        goto fail;
    for (size_t i = 0; i < sizeof(parts) / sizeof(parts[0]); ++i) {
        if (!parts[i] || !parts[i][0])
            continue;
        if (count && !nmxAudioAppend(out, capacity, &used,
            nmxAudioText(locale, NMX_AUDIO_TEXT_NAME_SEPARATOR)))
            goto fail;
        if (!nmxAudioAppend(out, capacity, &used, parts[i]))
            goto fail;
        ++count;
    }
    if (has_codec && count &&
        !nmxAudioAppend(out, capacity, &used, nmxAudioText(locale, NMX_AUDIO_TEXT_NAME_CLOSE)))
        goto fail;
    return count != 0 || has_codec;
fail:
    out[0] = '\0';
    return 0;
}

#endif
