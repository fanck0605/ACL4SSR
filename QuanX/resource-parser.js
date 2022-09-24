$notify("hello", "hello", $resource.content)

const parserList = {
    quanX: (function ($resource) {
        function convertRulePolicy(rule, policyMap) {
            const [type, value, policy] = rule.split(/\s*,\s*/)
            return `${type},${value},${policyMap[policy.toUpperCase()]}`
        }

        return {
            support() {
                return true
            },
            parse() {
                const policyMap = {
                    "APPLE": "🚀 节点选择",
                    "APPLE MUSIC": "🚀 节点选择",
                    "APPLE DOMESTIC": "🎯 全球直连",
                    "PROXY": "🚀 节点选择"
                }

                const ruleList = $resource.content
                    .split(/\r?\n/)
                    .filter(line => line)
                    .filter(line => !line.startsWith("#"))

                return `host-suffix,aaplimg.com,Apple
host-suffix,apple.co,Apple
host-suffix,apple.com,Apple
`
                
                return ruleList
                    .map(rule => convertRulePolicy(rule, policyMap))
                    .slice(0,3)
                    .join('\n')
            },
        }
    })($resource)
}


let isDone = false;

for (const parser of Object.values(parserList)) {
    if (parser.support()) {
        const result = {
            content: parser.parse()
        }
        $notify("hello", "hello", result.content)
        $done(result)
        isDone = true
        break;
    }
}

if (!isDone) {
    $done({
        error: "not supported!"
    })
}
