-- ERC-8004 agents: the on-chain agentWallet resolved at issuance (the key that signs for the agent).
ALTER TABLE agents ADD COLUMN agent_wallet TEXT;
