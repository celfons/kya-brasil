-- D-16: what the daily review needs to check the e-CNPJ against its AC's CRL. All public data:
-- serial number, the AC certificate (base64 DER) and the CRL URLs; never the signer's CPF.
ALTER TABLE agents ADD COLUMN certificate_serial TEXT;
ALTER TABLE agents ADD COLUMN certificate_issuer_der TEXT;
ALTER TABLE agents ADD COLUMN certificate_crl_urls TEXT;          -- JSON array
ALTER TABLE agents ADD COLUMN last_revocation_check_at TEXT;
-- Why a credential is suspended, so the review only reinstates what it suspended itself:
-- 'registration' (CNPJ not ATIVA; also legacy KYB suspensions, D-15) | 'certificate' (e-CNPJ on hold at its AC)
-- | 'wallet' (ERC-8004 wallet changed).
ALTER TABLE agents ADD COLUMN suspension_cause TEXT;
UPDATE agents SET suspension_cause = CASE WHEN status_reason LIKE 'agent wallet changed%' THEN 'wallet' ELSE 'registration' END WHERE status = 'suspended';
