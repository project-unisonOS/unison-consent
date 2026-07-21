# Actuation Consent Guidance

- Physical/high-impact actions should include `policy_context.consent_reference` in the Action Envelope.
- Recommended scopes: `actuation.*`, with finer scopes `actuation.home.*`, `actuation.robot.*`, `actuation.desktop.*`.
- For high-risk actions (`risk_level=high` or `required_confirmations>0`), orchestrator should request explicit consent and store the resulting grant ID as `consent_reference`.
- Consent records should log `action_id`, `target.device_class`, and `intent.name` for audit.
