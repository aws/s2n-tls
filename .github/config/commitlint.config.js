// See rules configuration at https://commitlint.js.org/reference/rules-configuration.html#rules-configuration
module.exports = {
  extends: ['@commitlint/config-conventional'],
  rules: {
    'subject-case': [0],
    'body-max-line-length': [0],
    'footer-max-line-length': [0],
    'type-enum': [2, 'always', [
      'build', 'chore', 'ci', 'docs', 'feat', 'fix', 'perf', 'test'
    ]]
  },
  parserPreset: {
    parserOpts: {
      issuePrefixes: ['#']
    }
  },
  ignores: [
    (message) => message.includes('Co-authored-by:')
  ]
};

