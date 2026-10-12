# anchors

`icp-brasil.pem`: PEM bundle of the ICP-Brasil trust anchors (AC Raiz v2, v5, v10, v11, v12 and,
preferably, the accredited intermediate ACs from ACcompactado.zip), downloaded from the ITI repository
and reviewed before commit. The CD uploads it to the Worker's KV (`icp:anchors`) on every deploy.
Without it the issuer refuses every e-CNPJ proof. See docs/RUNBOOK.md.
