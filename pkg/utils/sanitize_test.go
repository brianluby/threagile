package utils

import "testing"

func TestSanitizeID(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "alphanumeric",
			input:    "MyApp123",
			expected: "myapp123",
		},
		{
			name:     "with spaces",
			input:    "My App Name",
			expected: "my_app_name",
		},
		{
			name:     "with special chars",
			input:    "app-name@2024!",
			expected: "app_name_2024_",
		},
		{
			name:     "with dots and slashes",
			input:    "com.example/app",
			expected: "com_example_app",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "already lowercase",
			input:    "myapp",
			expected: "myapp",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := SanitizeID(tt.input)
			if got != tt.expected {
				t.Errorf("SanitizeID(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}