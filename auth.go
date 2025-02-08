package auth

import (
	sq "github.com/Masterminds/squirrel"
	"github.com/go-playground/validator/v10"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	Id            int
	Email         string `validate:"required,email"`
	PasswordPlain string `validate:"required,min=8,max=30"`
}

type Authenticator interface {
	Register(args RegisterArgs) error
	Authenticate(args AuthenticateArgs) (int, error)
	ChangePassword(args ChangePasswordArgs) error
	ChangeEmail(args ChangeEmailArgs) error
	//TODO:
	// ResetPassword(args ResetPasswordArgs) error
}

type AuthSqlite struct {
	Db        sq.BaseRunner
	Validator *validator.Validate
}

type NewAuthSqliteArgs struct {
	db        sq.BaseRunner
	validator *validator.Validate
}

func NewAuthSqlite(args NewAuthSqliteArgs) AuthSqlite {
	if args.db == nil {
		panic("db can't be nil")
	}
	if args.validator == nil {
		args.validator = validator.New(validator.WithRequiredStructEnabled())
	}
	return AuthSqlite{
		Db:        args.db,
		Validator: args.validator,
	}
}

type RegisterArgs struct {
	Email           string `validate:"required,email"`
	PasswordPlain   string `validate:"required,min=8,max=30"`
	PasswordConfirm string `validate:"required,min=8,max=30,eqfield=PasswordPlain"`
}

func (a *AuthSqlite) Register(args RegisterArgs) (int, error) {
	err := a.Validator.Struct(args)
	if err != nil {
		return 0, err
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(args.PasswordPlain), bcrypt.DefaultCost)
	if err != nil {
		return 0, err
	}

	stmt := sq.Insert("auth_users").
		Columns("email", "password").
		Values(args.Email, hashedPassword).
		Suffix("returning id").
		RunWith(a.Db)

	var id int
	err = stmt.Scan(&id)
	if err != nil {
		return 0, err
	}

	return id, nil
}

type AuthenticateArgs struct {
	Email         string `validate:"required,email"`
	PasswordPlain string `validate:"required,min=8,max=30"`
}

func (a *AuthSqlite) Authenticate(args AuthenticateArgs) (int, error) {
	err := a.Validator.Struct(args)
	if err != nil {
		return 0, err
	}

	stmt := sq.Select("password", "id").
		From("auth_users").
		Where(sq.Eq{"email": args.Email}).
		RunWith(a.Db)

	var hashedPassword string
	var id int
	err = stmt.Scan(&hashedPassword, &id)
	if err != nil {
		return 0, err
	}

	err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(args.PasswordPlain))
	if err != nil {
		return 0, err
	}

	return id, nil
}

type ForceChangePasswordArgs struct {
	Id               int    `validate:"required"`
	NewPasswordPlain string `validate:"required,min=8,max=30,nefield=PasswordPlain"`
}

func (a *AuthSqlite) ForceChangePassword(args ForceChangePasswordArgs) error {
	err := a.Validator.Struct(args)
	if err != nil {
		return err
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(args.NewPasswordPlain), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	stmt := sq.Update("auth_users").
		Set("password", hashedPassword).
		Where(sq.Eq{"id": args.Id})

	_, err = stmt.Exec()
	if err != nil {
		return err
	}
	return nil
}

type ChangePasswordArgs struct {
	Email              string `validate:"required,email"`
	PasswordPlain      string `validate:"required,min=8,max=30"`
	NewPasswordPlain   string `validate:"required,min=8,max=30,nefield=PasswordPlain"`
	NewPasswordConfirm string `validate:"required,min=8,max=30,nefield=PasswordPlain"`
}

func (a *AuthSqlite) ChangePassword(args ChangePasswordArgs) error {
	err := a.Validator.Struct(args)
	if err != nil {
		return err
	}

	id, err := a.Authenticate(AuthenticateArgs{Email: args.Email, PasswordPlain: args.PasswordPlain})
	if err != nil {
		return err
	}
	err = a.ForceChangePassword(ForceChangePasswordArgs{
		Id:               id,
		NewPasswordPlain: args.PasswordPlain,
	})

	return nil
}

type ChangeEmailAdminArgs struct {
	Id           int    `validate:"required"`
	NewEmail     string `validate:"required,email,nefield=Email"`
	EmailConfirm string `validate:"required,email,nefield=Email"`
}

func (a *AuthSqlite) ForceChangeEmail(args ChangeEmailAdminArgs) error {
	stmt := sq.Update("auth_users").
		Set("email", args.NewEmail).
		Where(sq.Eq{"id": args.Id}).
		RunWith(a.Db)
	_, err := stmt.Exec()
	if err != nil {
		return err
	}

	return nil
}

type ChangeEmailArgs struct {
	Email         string `validate:"required,email"`
	PasswordPlain string `validate:"required,min=8,max=30"`
	NewEmail      string `validate:"required,email,nefield=Email"`
	EmailConfirm  string `validate:"required,email,nefield=Email"`
}

func (a *AuthSqlite) ChangeEmail(args ChangeEmailArgs) error {
	err := a.Validator.Struct(args)
	if err != nil {
		return err
	}

	id, err := a.Authenticate(AuthenticateArgs{
		Email:         args.Email,
		PasswordPlain: args.PasswordPlain,
	})
	if err != nil {
		return err
	}

	err = a.ForceChangeEmail(ChangeEmailAdminArgs{
		Id:           id,
		NewEmail:     args.NewEmail,
		EmailConfirm: args.EmailConfirm,
	})
	if err != nil {
		return err
	}

	return nil
}
