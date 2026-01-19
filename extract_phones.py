import re
import pandas as pd

INPUT_FILE = "sumbee-Хүний наймаа-2025 09 01-2025 12 31 1(Number).csv"
OUTPUT_FILE = "with_phone_extracted.csv"
SUSPICIOUS_FILE = "suspicious_numbers.csv"

df = pd.read_csv(INPUT_FILE, encoding="utf-8-sig")


# Phase 1: Patterns


# http(s) URL delete (with numbers)
url_pattern = re.compile(r"https?://\S+")

# /product/90026858 attached -> delete (any domain)
product_attached_pattern = re.compile(
    r"\b(?:https?://)?(?:www\.)?[a-z0-9.-]+\.[a-z]{2,}/product/\d+\b",
    re.I
)

# /product/ 90026858 OR /product/\n90026858 -> allow only whitespace-separated 8 digits (any domain)
product_split_pattern = re.compile(
    r"(?:https?://)?(?:www\.)?[a-z0-9.-]+\.[a-z]{2,}/product/\s+(\d{8})",
    re.I
)

# O/o -> 0 only near digit/space/dash
o_to_zero_pattern = re.compile(r"(?<=[0-9\-\s])[oO]|[oO](?=[0-9\-\s])")

# IPv4 like 80.68.20.212 -> suspicious, must NOT become phone
ip_pattern = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

# phone number formats (+976 optional) // allow multi whitespace around separators// allow bullet •
phone_pattern = re.compile(
    r"""
    (?:\+?976[ \t\-]?)?
    (?:
        # 8 digits contiguous
        [6-9]\d{7}

        # 4-4: 9509 6014 / 9509-6014 / 9509 - 6014 / 8857•9092
      | [6-9]\d{3}(?:(?:[ \t]+)|(?:[ \t]*[\-\.\•][ \t]*))\d{4}

        # 2-2-2-2: 88 90 15 06 / 88-90-15-06 / 88 - 90 - 15 - 06
      | [6-9]\d(?:(?:(?:[ \t]+)|(?:[ \t]*[\-\.\•][ \t]*))\d{2}){3}

        # 2 + 6: 99 447945 / 99-447945 / 99 - 447945
      | [5-9]\d(?:(?:[ \t]+)|(?:[ \t]*[\-\.\•][ \t]*))\d{6}
    )
    """,
    re.VERBOSE
)


# 9 digit / 10 digit (contiguous, no spaces)
nine_pattern = re.compile(r"\b\d{9}\b")
ten_pattern  = re.compile(r"\b\d{10}\b")

# 18+ digit contiguous -> bank/account/ID etc -> (suspicious only, NO OUTPUT)
long_digit_pattern = re.compile(r"\d{18,}")

def digits_only(s: str) -> str:
    return re.sub(r"\D", "", str(s))

def is_mn_phone8(x: str) -> bool:
    return len(x) == 8 and x[0] in "6789" and x.isdigit()



# Phase 2: Preprocess

def preprocess_text(text: str) -> str:
    t = str(text)

    # (A) O/o -> 0
    t = o_to_zero_pattern.sub("0", t)

    # (B) URL delete
    t = url_pattern.sub(" ", t)

    # (C) /product/XXXXXXXX attached delete
    t = product_attached_pattern.sub(" ", t)

    return t


# Phase 2.5: Masks


def mask_ip_addresses(t: str):
    """Mask IP addresses so they won't be interpreted as phones."""
    ips = ip_pattern.findall(t)
    if not ips:
        return t, []
    t2 = ip_pattern.sub(" <IPADDR> ", t)
    sus = [{"token": x, "reason": "Must IP address (domain/IP) Need check!!! -> NO OUTPUT"} for x in ips]
    return t2, sus

def mask_long_numbers(t: str):
    """Mask 18+ digit contiguous numbers (bank/account/ID)."""
    longs = long_digit_pattern.findall(t)
    if not longs:
        return t, []
    t2 = long_digit_pattern.sub(" <LONGNUM> ", t)
    sus = [{"token": x, "reason": "18+ digit contiguous (bank/account/etc) Need check!!! -> NO OUTPUT"} for x in longs]
    return t2, sus



# Phase 3: Candidate extraction

def extract_product_split_numbers(original_text: str):
    """
    /product/ [whitespace] 8 digit (only allowed in this case)
    """
    nums = product_split_pattern.findall(str(original_text))
    return [x for x in nums if is_mn_phone8(x)]

def extract_strict_phone_candidates(preprocessed_text: str):
    return phone_pattern.findall(preprocessed_text)

def extract_contiguous_candidates(preprocessed_text: str):
    nines = nine_pattern.findall(preprocessed_text)
    tens  = ten_pattern.findall(preprocessed_text)
    return nines, tens



# Phase 4: Normalize + Rules + Suspicious
def too_many_zeros(phone: str, min_zeros: int = 5) -> bool:
    return phone.count("0") >= min_zeros

def last4_all_zero(phone: str) -> bool:
    return phone.endswith("0000")


def normalize_and_apply_rules(product_nums, strict_matches, nines, tens, suspicious_from_masks):
    phones = []
    suspicious = []
    suspicious.extend(suspicious_from_masks)

    # product split case (allowed)
    phones.extend(product_nums)

    # strict matches -> normalize -> validate
    for m in strict_matches:
        d = digits_only(m)

        # +976xxxxxxxx -> last 8
        if len(d) == 11 and d.startswith("976"):
            d = d[-8:]

        if is_mn_phone8(d):
            phones.append(d)

    # 9 digit handling
    for m in nines:
        first8 = m[:8]
        last8  = m[-8:]
        picked = None

        if is_mn_phone8(first8):
            picked = first8
        elif is_mn_phone8(last8):
            picked = last8

        if picked:
            phones.append(picked)
            suspicious.append({"token": m, "reason": "9-digit contiguous -> trimmed to 8"})
        else:
            suspicious.append({"token": m, "reason": "9-digit contiguous but no plausible MN 8-digit inside"})

    # 10 digit handling (bank/age)
    for m in tens:
        first8 = m[:8]
        last8  = m[-8:]
        first_ok = is_mn_phone8(first8)
        last_ok  = is_mn_phone8(last8)

        if first_ok and not last_ok:
            phones.append(first8)
            suspicious.append({"token": m, "reason": "10-digit contiguous -> used first8"})
        elif last_ok and not first_ok:
            phones.append(last8)
            suspicious.append({"token": m, "reason": "10-digit contiguous -> used last8"})
        elif first_ok and last_ok:
            phones.append(first8)
            suspicious.append({"token": m, "reason": "10-digit contiguous -> both plausible, kept first8 only"})
        else:
            suspicious.append({"token": m, "reason": "10-digit contiguous looks like bank/account/foreignnumber -> NO OUTPUT(Need check!!!)"})

    # unique + final filter
    phones = list(dict.fromkeys([p for p in phones if is_mn_phone8(p)]))

    # suspicious rules based on FINAL phones (but KEEP output)
    for p in phones:
        if last4_all_zero(p):
            suspicious.append({"token": p, "reason": "Final phone endswith 0000 -> suspicious (but kept in output)"})
        if too_many_zeros(p, min_zeros=5):
            suspicious.append({"token": p, "reason": "Final phone has many zeros (+4) -> suspicious (but kept in output)"})

    final = ", ".join(phones) if phones else None
    return final, suspicious


# Phase 5: Row-level pipeline

def process_row(content):
    if pd.isna(content) or content is None:
        return None, []

    original = str(content)

    # Phase 3a: product split numbers (from original)
    product_nums = extract_product_split_numbers(original)

    # Phase 2: preprocess (O->0, URL delete, product attached delete)
    t = preprocess_text(original)

    # Phase 2.5: mask IP + long numbers (prevent false phones)
    t, ip_sus = mask_ip_addresses(t)
    t, long_sus = mask_long_numbers(t)
    mask_sus = ip_sus + long_sus

    # Phase 3b: strict phone + contiguous candidates
    strict_matches = extract_strict_phone_candidates(t)
    nines, tens = extract_contiguous_candidates(t)

    # Phase 4: normalize + rules
    return normalize_and_apply_rules(product_nums, strict_matches, nines, tens, mask_sus)



# Run

finals = []
sus_rows = []

for idx, row in df.iterrows():
    final, sus = process_row(row.get("Content"))
    finals.append(final)

    for item in sus:
        sus_rows.append({
            "row_index": idx,
            "token": item.get("token", ""),
            "reason": item.get("reason", "")
        })

df["Final"] = finals
df.to_csv(OUTPUT_FILE, index=False, encoding="utf-8-sig")

sus_df = pd.DataFrame(sus_rows)
sus_df.to_csv(SUSPICIOUS_FILE, index=False, encoding="utf-8-sig")

print("Saved:", OUTPUT_FILE)
print("Saved suspicious:", SUSPICIOUS_FILE)

