/**
 * One plain sentence per rule saying what an attacker or a bad day can do with the issue.
 * Shown next to the finding title (dashboard, PR comment). Keep each sentence short and literal:
 * describe the realistic worst case for the code shape the rule matches, no fear numbers.
 */
export const RULE_IMPACT: Readonly<Record<number, string>> = {
  // SaaS core
  23001: 'Any signed-in user can read or change every row in this table.',
  23002: 'The server trusts a session the browser can forge, so someone can act as another user.',
  23003: 'A user who can create objects can hijack this function and run code with its owner\'s rights.',
  23004: 'Anyone can edit the request and pay any price they like.',
  23005: 'Someone can guess the secret one character at a time by timing the responses.',
  23006: 'Anyone on the internet can trigger this scheduled job as often as they want.',
  23007: 'A user can rewrite the model\'s instructions and make it ignore your rules.',
  23008: 'One request header skips your middleware, including its login check.',
  // Access control on routes
  29301: 'Any signed-in user can open someone else\'s record by changing the id.',
  29302: 'Anyone, signed in or not, can change or delete records by picking the id.',
  29309: 'Any signed-in user can open someone else\'s record by changing the id.',
  // Injection and code execution
  24101: 'Someone can read, change or delete any data in the database.',
  29303: 'Someone can read, change or delete any data in the database.',
  3021: 'Someone can read, change or delete any data in the database.',
  9605: 'Someone can read, change or delete any data in the database.',
  18001: 'Someone can read, change or delete any data in the database.',
  18031: 'Someone can read, change or delete any data in the database.',
  3020: 'Someone can read other users\' documents or bypass a login check.',
  18041: 'Someone can run their own JavaScript inside your database queries.',
  18102: 'Someone can read other users\' documents or bypass a login check.',
  32: 'Someone can run their own code on your server.',
  8811: 'Someone can run their own code on your server.',
  24102: 'Someone can run their own commands on your server.',
  33: 'Someone can run their own commands on your server.',
  18003: 'Someone can run their own commands on your server.',
  24103: 'A crafted payload can run code on your server when it is loaded.',
  24001: 'A crafted payload can run code on your server when it is loaded.',
  18013: 'A crafted payload can run code on your server when it is loaded.',
  8801: 'A crafted payload can run code on your server when it is loaded.',
  8802: 'A crafted YAML file can run code on your server when it is loaded.',
  29105: 'Someone can make the app call any class or method they name.',
  24106: 'Someone can make the server load and run a file of their choice.',
  24104: 'An uploaded XML file can read files from your server.',
  24002: 'An uploaded XML file can read files from your server.',
  // XSS
  16: 'Someone can run script in other users\' browsers and act as them.',
  24105: 'Someone can run script in other users\' browsers and act as them.',
  // SSRF, paths, redirects, uploads
  34: 'Someone can make your server call internal services or cloud metadata.',
  29306: 'Someone can make your server call internal services or cloud metadata.',
  27101: 'Someone can make your server call internal services or cloud metadata.',
  8814: 'Someone can make your server call internal services or cloud metadata.',
  35: 'Someone can read files outside the folder you meant, like config or keys.',
  29305: 'Someone can read files outside the folder you meant, like config or keys.',
  24110: 'Someone can read files outside the folder you meant, like config or keys.',
  29503: 'Someone can read files outside the folder you meant, like config or keys.',
  24107: 'Someone can upload a script and get the server to run or serve it.',
  25: 'A link on your domain can send users to a phishing page.',
  // Secrets and crypto
  14: 'If the env var is missing, anyone can sign their own login tokens.',
  28808: 'Anyone with the repo can sign their own sessions or tokens.',
  43: 'Anyone with the repo can sign their own sessions or tokens.',
  8809: 'Anyone with the repo can sign their own sessions or tokens.',
  8825: 'Anyone with the repo can sign their own sessions or tokens.',
  18012: 'Anyone with the repo has this password or key.',
  13301: 'Anyone with the repo can decrypt or sign data with this key.',
  5045: 'Anyone with the repo has this private key.',
  5015: 'Anyone with the repo can spend your AI quota on your bill.',
  29797: 'Anyone who reads the code can log in with the hard-coded password.',
  29959: 'Every secret in the repository settings can end up in the workflow logs.',
  24108: 'If the database leaks, most passwords can be cracked quickly.',
  37: 'Hashes made this way can be forged or cracked.',
  13303: 'Someone can see patterns in the encrypted data or tamper with it.',
  38: 'Tokens made this way can be predicted.',
  8826: 'Tokens made this way can be predicted.',
  8122: 'Someone can guess a valid hash by timing the comparison.',
  29977: 'Any script injected into the page can steal a long-lived login.',
  // Database policies
  3: 'Every user can read or change every row this policy covers.',
  28005: 'Any user can overwrite or delete every file in the bucket.',
  // Config and infra
  7004: 'If the app is compromised, the attacker is root inside the container.',
  8: 'Any website can call this API from a visitor\'s browser.',
  28813: 'The debug console is reachable from the network and runs code.',
  8827: 'Requests with a forged Host header are accepted, which breaks reset links.',
  13103: 'Admin ports are open to the whole internet.',
  9303: 'Traffic can be read or changed on public Wi-Fi.',
  9305: 'Other apps on the phone can open this screen or service directly.',
  18032: 'A user can set fields you never meant them to, such as admin or owner.',
  27: 'One crafted string can freeze the server for seconds per request.',
  29618: 'The handler keeps running after it answers, which can crash or leak data.',
};

export function ruleImpact(ruleId: number): string | undefined {
  return RULE_IMPACT[ruleId];
}
