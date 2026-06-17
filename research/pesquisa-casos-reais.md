# Pesquisa de Casos Reais de Phishing — Semana 1

Cumprimento do requisito "estudo de 3-4 casos reais de phishing para referência
de design" (checkpoint Semana 1). Conteúdo pronto a colar/adaptar no relatório
técnico.

---

## Caso 1 — Campanha de phishing Microsoft 365 com bypass de MFA (KnowBe4, 2025)

**Fonte:** [KnowBe4 — Uncovering the Sophisticated Phishing Campaign Bypassing M365 MFA](https://blog.knowbe4.com/uncovering-the-sophisticated-phishing-campaign-bypassing-m365-mfa)

**Descrição:** Campanha em 5 fases. Nas fases 3-4, a vítima é levada a uma página
falsa (domínios como `logon[.]sharefileselfservices[.]cloud` e `sso-services[.]com`)
que pede o email e mostra um "device code" com instruções de "Secure
Authentication". Em vez de capturar a password diretamente nessa página falsa, a
vítima é reencaminhada para o portal **real** da Microsoft
(`microsoft.com/devicelogin`), onde introduz o código fornecido pelo atacante e
autentica-se com as suas credenciais genuínas e MFA — autorizando sem saber o
acesso do atacante.

**Indicadores técnicos:** domínios spoofed que imitam portais de SSO empresarial;
o truque central não é replicar visualmente a Microsoft, mas sim explorar a
confiança no domínio legítimo da Microsoft (o utilizador "vê" a Microsoft real e
pensa que está seguro).

**Ligação ao nosso projeto:** o nosso `login.html` segue a abordagem mais clássica
(clone visual direto, fluxo de 2 passos email→password) em vez desta técnica de
device-code, que é mais sofisticada e contorna MFA. Vale a pena referir esta
campanha no relatório como exemplo de **evolução do phishing além do credential
harvesting simples** que implementámos — e justificar que optámos pela abordagem
clássica por ser mais didática para demonstrar o ciclo captura→logging→deteção.

---

## Caso 2 — PhishTank: base de dados pública de phishing verificado

**Fonte:** [PhishTank — Join the fight against phishing](https://www.phishtank.com/) ·
[PhishTank FAQ](https://phishtank.com/faq.php/) ·
[PhishTank Developer Info](https://www.phishtank.com/developer_info.php)

**Descrição:** PhishTank (operado pela Cisco Talos) é uma plataforma colaborativa
onde qualquer pessoa submete URLs suspeitos e a comunidade vota para "verificar"
se são phishing reais. Cada submissão tem: ID, URL, data de report, estado
(verificado/não), utilizador submissor, captura de ecrã e detalhes técnicos. A
homepage lista submissões recentes (ex.: domínios como
`eagle-scribe.lovable.app` apareceram na lista de submissões recentes), e há uma
API gratuita para consulta automática.

**Indicadores técnicos:** muitos URLs reportados usam subdomínios de plataformas
gratuitas (Lovable, Vercel, etc.) em vez de domínios próprios — padrão que o
nosso `domain_check.py` já capta parcialmente (deteção de muitos pontos no
domínio, encurtadores), mas que poderia ser reforçado com uma lista de
plataformas de hosting gratuito conhecidas por abuso.

**Ligação ao nosso projeto:** este caso liga-se diretamente à tarefa "testes com
páginas reais de phishing conhecidas" (Semana 4). Vamos usar URLs verificados
desta base de dados como input ao `scanner.py` para validar se o
`domain_check.py` e o `html_check.py` os classificam corretamente como
SUSPEITO/PHISHING.

---

## Caso 3 — Phishing à Chave Móvel Digital (CMD) em Portugal

**Fonte:** [4gnews — Alerta Chave Móvel Digital: novo golpe de phishing em Portugal](https://4gnews.pt/alerta-chave-movel-digital-novo-golpe-de-phishing-em-portugal/)

**Descrição:** Campanha multi-canal (smishing + vishing) que impersona a CMD —
sistema oficial de autenticação digital do Estado português. Vítimas recebem SMS
fraudulentos a alertar para "atividade suspeita" e a direcionar para sites falsos
que imitam a interface da CMD ou de bancos. Nesses sites falsos pedem números de
telefone associados à CMD e dados de acesso bancário. Há também contacto
telefónico direto (vishing) fazendo-se passar por funcionários da CMD ou do
banco.

**Indicadores técnicos:** uso combinado de SMS + chamada telefónica para
aumentar credibilidade antes de levar à página falsa — engenharia social em
múltiplos canais, não só web.

**Recomendações do CNCS:** não clicar em links de SMS/chamadas não solicitadas,
nunca partilhar códigos de acesso por esses canais, ativar MFA sempre que
possível, reportar ao CERT.PT ou à Polícia Judiciária, e contactar imediatamente
o banco/CMD em caso de comprometimento.

**Ligação ao nosso projeto:** justifica o conteúdo da nossa `warning.html` —
as recomendações do CNCS (não partilhar credenciais por canais não verificados,
usar MFA) são exatamente o tipo de boas práticas que a página de awareness já
comunica à "vítima" após a simulação. Também reforça o aviso legal do README
(RGPD, Lei n.º 109/2009), já que este é um caso real fiscalizado pelas
autoridades portuguesas.

---

## Caso 4 — Campanha PayPal com infraestrutura legítima da Microsoft 365

**Fonte:** [SecurityWeek — PayPal Phishing Campaign Employs Genuine Links to Take Over Accounts](https://www.securityweek.com/paypal-phishing-campaign-employs-genuine-links-to-take-over-accounts/)

**Descrição:** Os atacantes registaram um tenant de teste do Microsoft 365
(gratuito durante 3 meses) e criaram uma Distribution List com os emails das
vítimas. O Microsoft 365 reescreve o remetente (Sender Rewrite Scheme), o que
faz os emails passarem os checks SPF/DKIM/DMARC — ou seja, o email chega como
genuinamente vindo do PayPal, com URLs reais do PayPal (não spoofed) e detalhes
de pagamento credíveis. Ao clicar, a vítima vê uma página de login **real** do
PayPal a pedir confirmação de pagamento. Ao autenticar-se para investigar, a
página liga automaticamente a conta da vítima ao email do atacante (presente no
campo "Para:" do email), dando-lhe controlo da conta.

**Indicadores técnicos:** não há domínio falso nem página clonada — todo o
ataque usa infraestrutura 100% legítima (Microsoft + PayPal), o que o torna
invisível a heurísticas de domínio/SSL/HTML. A engenharia social explora
urgência (pedido de pagamento inesperado) para levar a vítima a agir sem
verificar.

**Ligação ao nosso projeto:** este é o caso mais importante para uma secção de
**limitações** no relatório técnico — mostra que o nosso scanner (baseado em
heurísticas de domínio, TLS, headers e HTML) **não detetaria este ataque**,
porque não há nada de tecnicamente anómalo a analisar. É um bom argumento para
justificar a necessidade de comparação com ferramentas como o VirusTotal
(que cruza reputação histórica, não só estrutura técnica) e para o objetivo do
mini-projeto de "comparar eficácia da deteção manual com ferramentas existentes".

---

## Resumo comparativo (para o relatório)

| Caso | Vetor principal | O nosso scanner detetaria? |
|---|---|---|
| 1. M365 device-code | Abuso de fluxo OAuth legítimo | Não (sem página falsa clássica) |
| 2. PhishTank (geral) | Domínios/hosting gratuito abusado | Sim — heurísticas de domínio cobrem isto |
| 3. CMD Portugal | Smishing + vishing multi-canal | Parcial — só a parte web seria analisável |
| 4. PayPal/M365 | Infraestrutura 100% legítima | Não — nenhum indicador técnico anómalo |

Esta tabela é útil para o relatório técnico como evidência de que heurísticas
têm limites claros, motivando a comparação com VirusTotal como complemento.

---

## Checklist

- [x] Caso 1 — Microsoft 365 (KnowBe4) preenchido com fonte e link
- [x] Caso 2 — PhishTank preenchido com fonte e link
- [x] Caso 3 — CNCS / Chave Móvel Digital preenchido com fonte e link
- [x] Caso 4 — PayPal/M365 preenchido com fonte e link
- [ ] Colar/adaptar estas secções no relatório técnico final
