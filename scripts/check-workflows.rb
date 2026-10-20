# Workflow lint: the rules that keep the release pipeline from leaking its signing key.
# Run through scripts/check-workflows.sh. Parses the YAML (so comments, flow style and quoted keys
# cannot hide anything) and checks the structure:
#
#   W1 every `uses:` is ./local or owner/repo[/path]@<40 hex commit> (or docker://...@sha256:<64 hex>)
#   W2 a top-level `permissions:` exists and grants nothing above read; no `write-all` anywhere
#   W3 a workflow that reads a secret other than GITHUB_TOKEN triggers on `push` of tags only
#      (no branches, no pull_request*, workflow_run, workflow_dispatch, workflow_call, ...)
#   W4 no `${{ github.event.` or `${{ github.head_ref` outside an `if:` (script injection)
#   W5 the file parses as YAML
#   W6 a secret expression is the whole value of one key under a step's `env:` or `with:`; never
#      inside a `run:` script, in a job-level or top-level `env:`, or as `secrets: inherit`
#
# It catches honest mistakes. Somebody who can push to the repository can edit this file too:
# the protection against that is the repository's settings (docs/RELEASING.md, section 1).
require 'yaml'

root = ARGV[0] || '.'
dir = File.join(root, '.github', 'workflows')
files = Dir.glob(File.join(dir, '*.{yml,yaml}')).sort
if files.empty?
  puts "FAIL: W0: #{dir}: no workflow files found"
  exit 1
end

PIN = %r{\A[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(/[A-Za-z0-9_./-]+)?@[0-9a-f]{40}\z}
DOCKER_PIN = %r{\Adocker://\S+@sha256:[0-9a-f]{64}\z}
EXPRESSION = /\$\{\{.*?\}\}/m
WHOLE_SECRET = /\A\$\{\{\s*secrets\.[A-Za-z_][A-Za-z0-9_]*\s*\}\}\z/

$failures = 0
def fail_rule(rule, file, where, detail)
  puts "FAIL: #{rule}: #{file}: #{where}: #{detail}"
  $failures += 1
end

# Yields every String (key and value alike) with its path and the name of the nearest key.
def each_string(node, path = [], key = nil, &block)
  case node
  when Hash
    node.each do |k, v|
      yield k.to_s, path + [k.to_s], 'key' if k.is_a?(String)
      each_string(v, path + [k.to_s], k.to_s, &block)
    end
  when Array
    node.each_with_index { |v, i| each_string(v, path + [i], key, &block) }
  when String
    yield node, path, key
  end
end

# Yields every Hash entry with its path.
def each_entry(node, path = [], &block)
  case node
  when Hash
    node.each do |k, v|
      yield k.to_s, v, path + [k.to_s]
      each_entry(v, path + [k.to_s], &block)
    end
  when Array
    node.each_with_index { |v, i| each_entry(v, path + [i], &block) }
  end
end

# Secret expressions other than the workflow's own GITHUB_TOKEN.
def secret_expressions(text)
  text.scan(EXPRESSION).select do |expression|
    expression.gsub(/secrets\.GITHUB_TOKEN\b/, '').match?(/(?<![A-Za-z0-9_])secrets(?![A-Za-z0-9_])/)
  end
end

def trigger_names(doc)
  on = doc.key?('on') ? doc['on'] : doc[true]
  case on
  when String then [on]
  when Array then on.map(&:to_s)
  when Hash then on.keys.map(&:to_s)
  else []
  end
end

def tag_push_only?(doc)
  on = doc.key?('on') ? doc['on'] : doc[true]
  return false unless on.is_a?(Hash) && on.keys.map(&:to_s) == ['push']
  push = on.values.first
  push.is_a?(Hash) && push.keys.map(&:to_s) == ['tags'] && push.values.first.is_a?(Array) && !push.values.first.empty?
end

files.each do |file|
  name = file.sub(%r{\A#{Regexp.escape(root)}/?}, '')
  begin
    doc = YAML.safe_load(File.read(file))
  rescue StandardError, SyntaxError => e
    fail_rule 'W5', name, '-', "does not parse as YAML (#{e.class})"
    next
  end
  unless doc.is_a?(Hash)
    fail_rule 'W5', name, '-', 'is not a YAML mapping'
    next
  end

  # W1
  each_entry(doc) do |key, value, path|
    next unless key == 'uses'
    where = path.join('.')
    unless value.is_a?(String)
      fail_rule 'W1', name, where, 'uses: is not a string'
      next
    end
    next if value.start_with?('./')
    fail_rule 'W1', name, where, "uses: #{value} is not pinned to a 40-hex commit" unless value.match?(PIN) || value.match?(DOCKER_PIN)
  end

  # W2
  permissions = doc['permissions']
  if permissions.nil?
    fail_rule 'W2', name, '-', 'no top-level permissions:'
  elsif permissions.is_a?(String)
    fail_rule 'W2', name, 'permissions', "permissions: #{permissions} is more than read" unless permissions == 'read-all'
  elsif permissions.is_a?(Hash)
    permissions.each do |scope, level|
      fail_rule 'W2', name, "permissions.#{scope}", "the top-level default grants #{level}: raise it in the job that needs it" unless %w[read none].include?(level.to_s)
    end
  else
    fail_rule 'W2', name, 'permissions', 'permissions: is not a mapping'
  end
  each_entry(doc) do |key, value, path|
    fail_rule 'W2', name, path.join('.'), 'write-all grants everything' if key == 'permissions' && value == 'write-all'
  end

  # W3 and W6 need to know whether a secret is read
  reads_secrets = false
  each_entry(doc) { |key, _value, _path| reads_secrets = true if key == 'secrets' }
  each_string(doc) { |text, _path, _key| reads_secrets = true unless secret_expressions(text).empty? }
  if reads_secrets && !tag_push_only?(doc)
    fail_rule 'W3', name, 'on', "reads secrets but is triggered by #{trigger_names(doc).join(', ')}: only `push` of tags may hold secrets"
  end

  # W4
  each_string(doc) do |text, path, key|
    next if key == 'if' || key == 'key'
    if text.match?(/\$\{\{[^}]*\bgithub\.(event\.|head_ref)/)
      fail_rule 'W4', name, path.join('.'), 'untrusted value interpolated: pass it through env: instead'
    end
  end

  # W6
  each_entry(doc) do |key, _value, path|
    fail_rule 'W6', name, path.join('.'), 'secrets: passes every secret to a called workflow' if key == 'secrets'
  end
  each_string(doc) do |text, path, key|
    next if key == 'key'
    secret_expressions(text).each do |expression|
      inside_step = path.include?('steps') && %w[env with].include?(path[-2].to_s)
      unless text.match?(WHOLE_SECRET) && inside_step
        fail_rule 'W6', name, path.join('.'), "#{expression} must be the whole value of a key under a step's env: or with:"
      end
    end
  end
end

exit 1 if $failures > 0
puts 'workflow lint: ok'
