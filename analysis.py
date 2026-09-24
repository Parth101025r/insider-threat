import keras
import joblib
import pandas as pd
import pandas as pd
import numpy as np
import datetime
import logging
import time


logger = logging.getLogger(__name__)

FEATURE_COLUMNS = [
    "Zscore_numDeviceEvents",
    "Zscore_numLogonEvents",
    "Zscore_numOffHourLogons",
    "numWikileaksVisits",
    "numJobsiteVisits",
    "numDropboxVisits",
    "numPersonalMails",
    "max_sizeDeviation",
    "mean_sizeDeviation",
    "max_attachDeviation",
    "mean_attachDeviation",
    "Zscore_numFileEvents",
    "Zscore_numUniqueFiles",
    "Zscore_numZip",
    "Zscore_numExe",
    "Zscore_numDoc"
]


ANN_MODEL = keras.models.load_model("D:\\Projects\\Insider Threat\\models\\ann_model.keras")
RF_MODEL = joblib.load("D:\\Projects\\Insider Threat\\models\\rf_model.joblib")


def preprocess(df):
    df = df.copy()

    # The trained models accept an already prepared feature CSV as well as raw logs.
    prepared_columns = set(FEATURE_COLUMNS).issubset(df.columns)
    if prepared_columns:
        prepared = df[FEATURE_COLUMNS].apply(pd.to_numeric, errors="coerce")
        prepared.replace([np.inf, -np.inf], 0, inplace=True)
        return prepared.fillna(0)

    # --------------------------------------------------
    # Required columns
    # --------------------------------------------------
    required_columns = [
        "user",
        "dateOnly",
        "numDeviceEvents",
        "numLogonEvents",
        "numOffHourLogons",
        "Zscore_numDeviceEvents",
        "Zscore_numLogonEvents",
        "Zscore_numOffHourLogons",
        "numWikileaksVisits",
        "numJobsiteVisits",
        "numDropboxVisits",
        "numPersonalMails",
        "max_sizeDeviation",
        "mean_sizeDeviation",
        "max_attachDeviation",
        "mean_attachDeviation",
        "numFileEvents",
        "numUniqueFiles",
        "numZip",
        "numExe",
        "numDoc",
        "Zscore_numFileEvents",
        "Zscore_numUniqueFiles",
        "Zscore_numZip",
        "Zscore_numExe",
        "Zscore_numDoc"
    ]

    # --------------------------------------------------
    # Convert date if available
    # --------------------------------------------------
    if "date" in df.columns:
        df["date"] = pd.to_datetime(df["date"], errors="coerce")
        df["dateOnly"] = df["date"].dt.date

    elif "dateOnly" not in df.columns:
        df["dateOnly"] = 0

    # --------------------------------------------------
    # Make sure user exists
    # --------------------------------------------------
    if "user" not in df.columns:
        df["user"] = 0

    # --------------------------------------------------
    # Device features
    # --------------------------------------------------
    if "activity" in df.columns:
        device_counts = df.groupby(["user", "dateOnly"])["activity"].transform("count")
        df["numDeviceEvents"] = device_counts
    else:
        df["numDeviceEvents"] = 0

    # --------------------------------------------------
    # Logon features
    # --------------------------------------------------
    if "activity" in df.columns and "logon" in df.columns:
        start_time = datetime.time(8, 0)
        end_time = datetime.time(18, 0)

        df["timeOnly"] = pd.to_datetime(
            df["date"], errors="coerce"
        ).dt.time

        df["isOffHours"] = df["timeOnly"].apply(
            lambda t: 0 if pd.isna(t)
            else int(t < start_time or t > end_time)
        )

        df["numLogonEvents"] = df.groupby(
            ["user", "dateOnly"]
        )["activity"].transform("count")

        df["numOffHourLogons"] = df.groupby(
            ["user", "dateOnly"]
        )["isOffHours"].transform("sum")
    else:
        df["numLogonEvents"] = 0
        df["numOffHourLogons"] = 0

    # --------------------------------------------------
    # HTTP features
    # --------------------------------------------------
    if "url" in df.columns:
        url = df["url"].fillna("").astype(str)

        df["isWikileaks"] = url.str.contains(
            "wikileaks|leaks", case=False, na=False
        )

        df["isJobsite"] = url.str.contains(
            "indeed|monster|careerbuilder|linkedin|job|hire",
            case=False,
            na=False
        )

        df["isDropbox"] = url.str.contains(
            "dropbox|storage|cloud|GB|TB",
            case=False,
            na=False
        )

        df["numWikileaksVisits"] = df.groupby(
            ["user", "dateOnly"]
        )["isWikileaks"].transform("sum")

        df["numJobsiteVisits"] = df.groupby(
            ["user", "dateOnly"]
        )["isJobsite"].transform("sum")

        df["numDropboxVisits"] = df.groupby(
            ["user", "dateOnly"]
        )["isDropbox"].transform("sum")
    else:
        df["numWikileaksVisits"] = 0
        df["numJobsiteVisits"] = 0
        df["numDropboxVisits"] = 0

    # --------------------------------------------------
    # Email features
    # --------------------------------------------------
    if "to" in df.columns:
        personalMails = ["gmail", "yahoo", "hotmail", "outlook"]

        df["isPersonal"] = df["to"].fillna("").astype(str).str.contains(
            "|".join(personalMails),
            case=False,
            na=False
        )

        df["numPersonalMails"] = df.groupby(
            ["user", "dateOnly"]
        )["isPersonal"].transform("sum")
    else:
        df["numPersonalMails"] = 0

    if "size" in df.columns:
        df["size"] = pd.to_numeric(df["size"], errors="coerce").fillna(0)

        mean_size = df.groupby("user")["size"].transform("mean")
        std_size = df.groupby("user")["size"].transform("std")

        df["sizeDeviation"] = np.where(
            std_size == 0,
            0,
            (df["size"] - mean_size) / std_size
        )

        df["max_sizeDeviation"] = df.groupby(
            ["user", "dateOnly"]
        )["sizeDeviation"].transform("max")

        df["mean_sizeDeviation"] = df.groupby(
            ["user", "dateOnly"]
        )["sizeDeviation"].transform("mean")
    else:
        df["max_sizeDeviation"] = 0
        df["mean_sizeDeviation"] = 0

    if "attachments" in df.columns:
        df["attachments"] = pd.to_numeric(
            df["attachments"], errors="coerce"
        ).fillna(0)

        mean_attach = df.groupby("user")["attachments"].transform("mean")
        std_attach = df.groupby("user")["attachments"].transform("std")

        df["attachDeviation"] = np.where(
            std_attach == 0,
            0,
            (df["attachments"] - mean_attach) / std_attach
        )

        df["max_attachDeviation"] = df.groupby(
            ["user", "dateOnly"]
        )["attachDeviation"].transform("max")

        df["mean_attachDeviation"] = df.groupby(
            ["user", "dateOnly"]
        )["attachDeviation"].transform("mean")
    else:
        df["max_attachDeviation"] = 0
        df["mean_attachDeviation"] = 0

    # --------------------------------------------------
    # File features
    # --------------------------------------------------
    if "filename" in df.columns:

        df["ext"] = (
            df["filename"]
            .fillna("")
            .astype(str)
            .str.extract(r"\.([^.]+)$")[0]
            .str.lower()
        )

        df["numFileEvents"] = df.groupby(
            ["user", "dateOnly"]
        )["filename"].transform("count")

        df["numUniqueFiles"] = df.groupby(
            ["user", "dateOnly"]
        )["filename"].transform("nunique")

        df["numZip"] = df["ext"].eq("zip").groupby(
            [df["user"], df["dateOnly"]]
        ).transform("sum")

        df["numExe"] = df["ext"].eq("exe").groupby(
            [df["user"], df["dateOnly"]]
        ).transform("sum")

        df["numDoc"] = df["ext"].isin(
            ["doc", "docx", "pdf", "txt"]
        ).groupby(
            [df["user"], df["dateOnly"]]
        ).transform("sum")

    else:
        for col in [
            "numFileEvents",
            "numUniqueFiles",
            "numZip",
            "numExe",
            "numDoc"
        ]:
            df[col] = 0

    # --------------------------------------------------
    # Calculate Z-scores
    # --------------------------------------------------
    zscore_columns = [
        "numDeviceEvents",
        "numLogonEvents",
        "numOffHourLogons",
        "numFileEvents",
        "numUniqueFiles",
        "numZip",
        "numExe",
        "numDoc"
    ]

    for col in zscore_columns:

        mean_value = df.groupby("user")[col].transform("mean")
        std_value = df.groupby("user")[col].transform("std")

        df[f"Zscore_{col}"] = np.where(
            (std_value == 0) | (std_value.isna()),
            0,
            (df[col] - mean_value) / std_value
        )

    # --------------------------------------------------
    # Keep only required ML features
    # --------------------------------------------------
    # Missing features → 0
    for col in FEATURE_COLUMNS:
        if col not in df.columns:
            df[col] = 0

    # Remove everything unnecessary
    df = df[FEATURE_COLUMNS]

    # Replace any remaining NaN / infinite values
    df.replace([np.inf, -np.inf], 0, inplace=True)
    df.fillna(0, inplace=True)

    return df

def getPredictions(file):
    data = preprocess(file)
    logger.info("ANN prediction started for %d rows", len(data))
    ann_start = time.perf_counter()
    annPreds = ANN_MODEL.predict(data, verbose=0).flatten()
    logger.info(
        "ANN prediction completed in %.3f seconds",
        time.perf_counter() - ann_start
    )

    logger.info("Random Forest prediction started for %d rows", len(data))
    rf_start = time.perf_counter()
    rfPreds = RF_MODEL.predict_proba(data)[:, 1]
    logger.info(
        "Random Forest prediction completed in %.3f seconds",
        time.perf_counter() - rf_start
    )

    predsProbabs = 0.55*rfPreds + 0.45*annPreds
    preds = (predsProbabs > 0.5).astype(int)
    return preds



