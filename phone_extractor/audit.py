import pandas as pd

df = pd.read_csv("with_phone_extracted.csv", encoding="utf-8-sig")

end_row = 9000
end_row = min(end_row, len(df) - 1)

out = df.loc[0:end_row, ["Final"]].copy()

# NaN 
out["Final"] = out["Final"].fillna("NaN").astype(str).str.strip()

#

out.to_csv(
    "extracted_numbers_0_9000.csv",
    index=False,
    header=False,
    encoding="utf-8-sig"
)

print("Saved:", "extracted_numbers_0_9000.csv")

