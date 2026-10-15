-- The mandate requested with each challenge (snapshot at registration or renewal). Issuance uses this one, not the
-- agent row's current mandate, so a later registration cannot change what a holder already signed for. Challenges
-- created before this migration have NULL and are refused (they expire within 15 minutes anyway).
ALTER TABLE challenges ADD COLUMN mandate TEXT;
