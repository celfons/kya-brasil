# H3 codebook: coding the open answers

Written on 2026-11-06, **before any participant report was read**. Use it to code the open answers that `analyze.py`
groups in `answers.md` (q1–q5, the library-change answers), and the notes of the post-session interview when there is
one. A code applies to a passage (a sentence or a clause), and one passage may take more than one code.

## Procedure

1. Two coders: the author and one independent coder who did not take part in the study and did not write the library.
2. Each coder codes **every** report alone, with this codebook only.
3. Agreement is computed per passage and code (Cohen's kappa) and reported, with the number of passages.
4. Disagreements are discussed and resolved; the resolution and its reason are recorded. The codebook is not changed
   to fit the data. A passage that fits no code goes to `OTHER` with a note; new codes, if any, are reported as
   emergent, apart from these.
5. Each claim in the results cites at least one coded passage **and** one measured datum from the report (attempts,
   error category, sub-case, time). A claim with only one of the two is reported as weaker.
6. Each participant receives the summary of their own case and is asked whether it represents what happened (member
   checking). Their comments are recorded next to the summary.

## Codes

| Code | Definition | Example passage | Usually confirmed by |
| --- | --- | --- | --- |
| `DOC-MISSING` | something the participant needed is not in the documentation | "não achei como ler o corpo depois de autenticar" | many attempts in one task; `runtime` or `other` errors |
| `DOC-UNCLEAR` | it is in the documentation but was misunderstood or hard to find | "o exemplo do README não dizia que precisava do await" | errors that stop after a docs-related change |
| `DOC-LANGUAGE` | the language of the documentation (English) got in the way | "em português" | — (self-report only) |
| `API-NAMING` | names or shapes of the library's functions or fields were confusing or guessed wrong | "inventei o nome da função" | missing-import errors; `contract` errors |
| `API-ERROR-MSG` | an error message from the library or the kit helped or misled | "a mensagem dizia assinatura, mas era o relógio" | the category of the error that followed |
| `CONCEPT-PKI` | ICP-Brasil, certificates, CRL, chain or revocation concepts were hard | "não entendi o nextUpdate" | `icp_chain`, `revocation`, `freshness` errors |
| `CONCEPT-MANDATE` | expressing the mandate (ceilings, counterparties, validity, delegation) was hard | "não sabia se 30 dias era validade ou ttl" | T2 grade other than `correct`; deviating fields |
| `AI-HELPED` | an AI assistant helped | "o assistente montou a cadeia" | `ai_assistant.used`; tasks listed |
| `AI-MISLED` | an AI assistant produced wrong code or APIs that do not exist | "a IA inventou verificarRequisicao" | missing-import or `runtime` errors early on |
| `LIB-CHANGE-NEED` | the participant felt they had to change or work around the library | "tive de copiar a função" | `library_change.changed`; `library_integrity.modified` |
| `KIT-ISSUE` | a problem of the kit itself (installation, feedback, crash), not of the library or docs | "o check travou" | kit errors; reported to the researcher |
| `ADOPTION-YES` | would use it in a real system | "sim" | q4 |
| `ADOPTION-BARRIER` | what would stop use in a real system (cost, legal doubt, effort, trust) | "o cliente não tem e-CNPJ" | q4 |
| `OTHER` | none of the above; note what it is | | |

## Reporting

Per participant: the codes with their passages and the measured data that confirm them. Across participants: how many
had each code, never a percentage with three people. Report the participants who did not finish, and what they
coded, in the same way.
