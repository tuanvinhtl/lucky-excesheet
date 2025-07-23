function verify(key, secretKey) {
  try {
    const decoded = Buffer.from(key, "base64").toString("utf8");
    const [userId, timestamp, signature] = decoded.split(":");
    const validSig = crypto
      .createHmac("sha256", secretKey)
      .update(`${userId}:${timestamp}`)
      .digest("hex");

    const isValid = signature === validSig;

    // Optional: check expiration
    const issuedAt = parseInt(timestamp, 10);
    const now = Date.now();
    const thirtyDays = 30 * 24 * 60 * 60 * 1000;

    const isNotExpired = now - issuedAt <= thirtyDays;

    return isValid && isNotExpired;
  } catch (err) {
    return false;
  }
}

export { verify };
