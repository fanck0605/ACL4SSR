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


                return ruleList.map(rule => convertRulePolicy(rule, policyMap)).join('\n')
            },
        }
    })($resource)
}


let isDone = false;

for (const parser of Object.values(parserList)) {
    if (parser.support()) {
        $done({
            content: parser.parse()
        })
        isDone = true
        break;
    }
}

if (!isDone) {
    $done({
        error: "not supported!"
    })
}
