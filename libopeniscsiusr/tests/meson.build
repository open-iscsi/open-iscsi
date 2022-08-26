# tests for libopeniscsiusr

# create an assocaitive array, where the
# thing being tested is the "key", and the
# source file for it is the "value

test_subjects = [
  'context',
  'iface',
  'node',
  'session']

test_arr = {}
foreach s: test_subjects
  test_arr += {s: files('test_' + s + '.c')}
endforeach
