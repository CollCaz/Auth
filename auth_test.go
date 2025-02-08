package auth

import (
	"database/sql"
	"fmt"
	"os"
	"testing"

	_ "github.com/mattn/go-sqlite3"
	"github.com/pressly/goose/v3"
)

//TODO: make it so tests check the database for the expected changes

var db *sql.DB

func getDb(t *testing.T) *sql.DB {
	if db != nil {
		return db
	}
	var err error
	db, err = sql.Open("sqlite3", "file::memory:?cache=shared&mode=rw&_journal_mode=WAL")
	if err != nil {
		t.Fatalf("failed to open in memory db: %s", err.Error())
		return nil
	}
	db.SetMaxOpenConns(1)
	migrationsDir := os.Getenv("GOOSE_MIGRATION_DIR")
	err = goose.SetDialect("sqlite3")
	if err != nil {
		t.Fatalf("faield to set dialect: %s", err.Error())
		return nil
	}

	err = goose.Up(db, migrationsDir)
	goose.SetVerbose(true)
	if err != nil {
		fmt.Println(migrationsDir)
		t.Fatalf("failed to apply database migrations: %s", err.Error())
		return nil
	}

	return db
}

func TestAuthSqlite_Register(t *testing.T) {
	t.Parallel()
	db := getDb(t)
	a := NewAuthSqlite(NewAuthSqliteArgs{db: db})
	tests := []struct {
		name         string
		registerArgs RegisterArgs

		wantErr bool
	}{
		{
			name: "test register",
			registerArgs: RegisterArgs{
				Email:           "testEmail@email.com",
				PasswordPlain:   "password",
				PasswordConfirm: "password",
			},
			wantErr: false,
		},
		{
			name: "test unique email",
			registerArgs: RegisterArgs{
				Email:           "testEmail@email.com",
				PasswordPlain:   "password",
				PasswordConfirm: "password",
			},
			wantErr: true,
		},
		{
			name: "test required email",
			registerArgs: RegisterArgs{
				Email:           "",
				PasswordPlain:   "password",
				PasswordConfirm: "password",
			},
			wantErr: true,
		},
		{
			name: "test invalid email",
			registerArgs: RegisterArgs{
				Email:           "test_invalid_email@email",
				PasswordPlain:   "password",
				PasswordConfirm: "password",
			},
			wantErr: true,
		},
		{
			name: "test passwords don't match",
			registerArgs: RegisterArgs{
				Email:           "testEmail@email.com",
				PasswordPlain:   "password",
				PasswordConfirm: "other_password",
			},
			wantErr: true,
		},
		{
			name: "test short password",
			registerArgs: RegisterArgs{
				Email:           "",
				PasswordPlain:   "ss",
				PasswordConfirm: "password",
			},
			wantErr: true,
		},
		{
			name: "test long password",
			registerArgs: RegisterArgs{
				Email: "test_long_pass@email.com",
				PasswordPlain: func() string {
					var pass []byte
					for i := 0; i < 32; i++ {
						pass = append(pass, 'a')
					}
					return string(pass)
				}(),
				PasswordConfirm: "password",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, gotErr := a.Register(tt.registerArgs)
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("Register() failed: %v", gotErr)
				}
				return
			}
			if tt.wantErr {
				t.Fatal("Register() succeeded unexpectedly")
			}
		})
	}
}

func TestAuthSqlite_Authenticate(t *testing.T) {
	t.Parallel()
	db := getDb(t)
	a := NewAuthSqlite(NewAuthSqliteArgs{db: db})
	id, err := a.Register(RegisterArgs{
		Email:           "LoginEmail@email.com",
		PasswordPlain:   "password",
		PasswordConfirm: "password",
	})
	if err != nil {
		t.Fatalf("Login() failed: %v", err)
	}
	tests := []struct {
		name string // description of this test case
		// Named input parameters for target function.
		loginArgs AuthenticateArgs
		want      int
		wantErr   bool
	}{
		{
			name: "test login",
			loginArgs: AuthenticateArgs{
				Email:         "LoginEmail@email.com",
				PasswordPlain: "password",
			},
			want:    id,
			wantErr: false,
		},
		{
			name: "test wrong password",
			loginArgs: AuthenticateArgs{
				Email:         "LoginEmail@email.com",
				PasswordPlain: "wrong_password",
			},
			wantErr: true,
		},
		{
			name: "test wrong email",
			loginArgs: AuthenticateArgs{
				Email:         "WrongLoginEmail@email.com",
				PasswordPlain: "password",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotErr := a.Authenticate(tt.loginArgs)
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("Login() failed: %v", gotErr)
				}
				return
			}
			if tt.wantErr {
				t.Fatal("Login() succeeded unexpectedly")
			}
			if got != tt.want {
				t.Fatalf("Login() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAuthSqlite_ChangePassword(t *testing.T) {
	t.Parallel()
	db := getDb(t)
	a := NewAuthSqlite(NewAuthSqliteArgs{db: db})
	tests := []struct {
		name string // description of this test case
		// Named input parameters for receiver constructor.
		// Named input parameters for target function.
		args    ChangePasswordArgs
		wantErr bool
	}{
		{
			name: "test change password",
			args: ChangePasswordArgs{
				Email:              "changePass@email.com",
				PasswordPlain:      "password",
				NewPasswordPlain:   "new_password",
				NewPasswordConfirm: "new_password",
			},
			wantErr: false,
		},
		{
			name: "test wrong password",
			args: ChangePasswordArgs{
				Email:              "changePass@email.com",
				PasswordPlain:      "wrong_password",
				NewPasswordPlain:   "new_password",
				NewPasswordConfirm: "new_password",
			},
			wantErr: true,
		},
		{
			name: "test password not confirmed",
			args: ChangePasswordArgs{
				Email:              "changePass@email.com",
				PasswordPlain:      "wrong_password",
				NewPasswordPlain:   "new_password",
				NewPasswordConfirm: "not_new_password",
			},
			wantErr: true,
		},
		{
			name: "test password not supplied",
			args: ChangePasswordArgs{
				Email:              "changePass@email.com",
				PasswordPlain:      "",
				NewPasswordPlain:   "new_password",
				NewPasswordConfirm: "not_new_password",
			},
			wantErr: true,
		},
		{
			name: "test email not supplied",
			args: ChangePasswordArgs{
				Email:              "",
				PasswordPlain:      "password",
				NewPasswordPlain:   "new_password",
				NewPasswordConfirm: "not_new_password",
			},
			wantErr: true,
		},
		{
			name: "test new password not supplied",
			args: ChangePasswordArgs{
				Email:              "",
				PasswordPlain:      "password",
				NewPasswordPlain:   "",
				NewPasswordConfirm: "",
			},
			wantErr: true,
		},
		{
			name: "test invalid new password ",
			args: ChangePasswordArgs{
				Email:              "",
				PasswordPlain:      "password",
				NewPasswordPlain:   "short",
				NewPasswordConfirm: "short",
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a.Register(RegisterArgs{
				Email:           "changePass@email.com",
				PasswordPlain:   "password",
				PasswordConfirm: "password",
			})
			gotErr := a.ChangePassword(tt.args)
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("ChangePassword() failed: %v", gotErr)
				}
				return
			}
			if tt.wantErr {
				t.Fatal("ChangePassword() succeeded unexpectedly")
			}
		})
	}
}

func TestAuthSqlite_ChangeEmail(t *testing.T) {
	t.Parallel()
	db := getDb(t)
	tests := []struct {
		name string // description of this test case
		// Named input parameters for receiver constructor.
		cargs NewAuthSqliteArgs
		// Named input parameters for target function.
		args    ChangeEmailArgs
		wantErr bool
	}{
		{
			name:  "test change email",
			cargs: NewAuthSqliteArgs{db: db},
			args: ChangeEmailArgs{
				Email:         "changeEmail@email.com",
				PasswordPlain: "password",
				NewEmail:      "newChangeEmail@email.com",
				EmailConfirm:  "newChangeEmail@email.com",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := NewAuthSqlite(tt.cargs)
			a.Register(RegisterArgs{
				Email:           "changeEmail@email.com",
				PasswordPlain:   "password",
				PasswordConfirm: "password",
			})
			gotErr := a.ChangeEmail(tt.args)
			if gotErr != nil {
				if !tt.wantErr {
					t.Errorf("ChangeEmail() failed: %v", gotErr)
				}
				return
			}
			if tt.wantErr {
				t.Fatal("ChangeEmail() succeeded unexpectedly")
			}
		})
	}
}
