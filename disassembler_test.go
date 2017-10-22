package go_javad

import (
	"fmt"
	"github.com/stretchr/testify/require"
	"io/ioutil"
	"testing"
)

func TestDisassemble(t *testing.T) {
	tests := []struct {
		classPath             string              // classPath is the target class path
		expectedInternalCalls map[string]struct{} // expectedInternalCalls are the expected internal methods that should be called during the program execution
		expectedLibraryCalls  map[string]struct{} // expectedInternalCalls are the expected library methods that should be called during the program execution
	}{
		{
			classPath: "test/classes/com/mycompany/app/App.class",
			expectedInternalCalls: map[string]struct{}{
				"com/mycompany/app/App.print":   struct{}{},
				"com/mycompany/app/Proc.<init>": struct{}{},
				"com/mycompany/app/Proc.run":    struct{}{},
			},
			expectedLibraryCalls: map[string]struct{}{
				"java/lang/Object.<init>":                   struct{}{},
				"java/io/PrintStream.println":               struct{}{},
				"java/lang/System.exit":                     struct{}{},
				"java/io/IOException.getMessage":            struct{}{},
				"java/lang/InterruptedException.getMessage": struct{}{},
				"java/util/concurrent/TimeUnit.sleep":       struct{}{},
				"java/io/PrintWriter.<init>":                struct{}{},
				"java/io/PrintWriter.printf":                struct{}{},
				"java/io/PrintWriter.close":                 struct{}{},
				"java/io/FileWriter.<init>":                 struct{}{},
			},
		},
		{
			classPath: "test/classes/com/mycompany/app/Main.class",
			expectedLibraryCalls: map[string]struct{}{
				"java/lang/System.exit":           struct{}{},
				"java/lang/System.getProperty":    struct{}{},
				"java/io/PrintStream.println":     struct{}{},
				"java/lang/StringBuffer.<init>":   struct{}{},
				"java/lang/StringBuffer.append":   struct{}{},
				"java/lang/StringBuffer.toString": struct{}{},
				"java/lang/String.length":         struct{}{},
				"java/lang/String.indexOf":        struct{}{},
				"java/lang/String.substring":      struct{}{},
				"java/lang/Double.parseDouble":    struct{}{},
				"java/lang/Object.<init>":         struct{}{},
			},
			expectedInternalCalls: map[string]struct{}{
				"com/google/gerrit/launcher/GerritLauncher.main": struct{}{},
				"Main.onSupportedJavaVersion":                    struct{}{},
				"Main.parse":                                     struct{}{},
			},
		},
	}
	for _, test := range tests {
		data, err := ioutil.ReadFile(test.classPath)
		require.NoError(t, err)
		calls, err := Disassemble(data)
		require.NoError(t, err)
		for _, l := range calls.library {
			key := fmt.Sprintf("%s.%s", l.path, l.method)
			if _, ok := test.expectedLibraryCalls[key]; !ok {
				require.FailNow(t, "Missing call in library list", "Call to %q must exist in library list", key)
			}
		}
		for _, in := range calls.internal {
			key := fmt.Sprintf("%s.%s", in.path, in.method)
			if _, ok := test.expectedInternalCalls[key]; !ok {
				require.FailNow(t, "Missing call in internal list", "Call to %q must exist in internal list", key)
			}
		}
	}
}
