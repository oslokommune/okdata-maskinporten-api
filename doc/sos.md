# Spørsmål og svar

Her samler vi opp spørsmål og svar på ting som har dukket opp hos brukere av
løsningen.

- [Feilmelding ved skriving av nøkkel til SSM](#feilmelding-ved-skriving-av-nøkkel-til-ssm)
- [Feilmelding om manglende tilgang til scope](#feilmelding-om-manglende-tilgang-til-scope)
- [Feilmelding om manglende delegering](#feilmelding-om-manglende-delegering)
- [Feilmelding om ukjent kid](#feilmelding-om-ukjent-kid)
- [Er klient- og nøkkel ID-er hemmelige?](#er-klient--og-nøkkel-id-er-hemmelige)

## Feilmelding ved skriving av nøkkel til SSM

Bruker får følgende feilmelding i `okdata-cli` ved forsøk på skriving av nøkkel
til SSM:

```
Something went wrong: User: arn:aws:sts::xxxxxxxxxxxx:assumed-role/okdata-maskinporten-api-prod-eu-west-1-lambdaRole/okdata-maskinporten-api-prod-app is not authorized to perform: sts:AssumeRole on resource: arn:aws:iam::xxxxxxxxxxxx:role/dataplatform-maskinporten
```

**Svar**: Dette tyder på at CloudFormation-stacken ikke er satt opp, eller at
den er satt opp feil. Brukeren kan prøve å slette eventuelt eksisterende stack,
og opprette den på nytt med siste versjon av
[malen](https://github.com/oslokommune/dataplattform/blob/master/origo/registerdata/offentlige-registerdata-3.md#%C3%A5pne-aws-konto).
Husk at `DATAPLATFORM_PROD_ACCOUNT` i malen må erstattes manuelt med
dataplattformens AWS-kontonummer for prod før kjøring.

## Feilmelding om manglende tilgang til scope

Bruker får feilmelding a la denne ved bruk av nøkkel mot Maskinporten:

```json
{
  "error": "forbidden",
  "error_description": "Consumer has not been granted access to the scope folkeregister:deling/offentligutenhjemmel. (correlation id: 2d4fa134-eacb-eae8-63f4-eeb2ea408979)"
}
```

**Svar**: Bruker mangler sannsynligvis å sette `consumer_org` til Oslo kommunes
organisasjonsnummer i forespørselen mot Maskinporten: `consumer_org=958935420`.

## Feilmelding om manglende delegering

Bruker får feilmelding a la denne ved bruk av nøkkel mot Maskinporten:

```json
{
  "error": "forbidden",
  "error_description": "Consumer 958935420 has not delegated access to the scope folkeregister:deling/offentligutenhjemmel to supplier 920204368. (correlation id: 2d40caf9-ea11-9710-d7fa-82639fe7374f)"
}
```

**Svar**: Her mangler det delegering av rettigheter fra Oslo kommunes
organisasjonsnummer (958935420) til Origos (920204368). Dette må løses på høyere
nivå, begynn med å ta kontakt på `#freg-tilgang-prosess`.

## Feilmelding om ukjent kid

Bruker får feilmelding a la denne ved bruk av nøkkel mot Maskinporten:

```json
{
  "error": "invalid_grant",
  "error_description": "Invalid assertion. Client authentication failed. Unknown key identifier (kid) for client. (correlation id: 023510ad-58bb-b65b-1623-107935a6bf95)"
}
```

**Svar**: Dobbeltsjekk at `iss` (issuer) er satt til riktig klient ID i
forespørselen mot Maskinporten (ID-en til klienten som nøkkelen tilhører, ikke
nøkkel ID-en).

## Er klient- og nøkkel ID-er hemmelige?

**Svar**: De er ikke veldig sensitive, men bør betraktes som intern informasjon
og unngås sjekket inn i offentlig synlige kodebaser.
