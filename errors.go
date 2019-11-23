package comarch

import "errors"

var (
	// ErrInvalidConfiguration некорректная конфигурация
	ErrInvalidConfiguration = errors.New("Invalid configuration")

	// ErrBadResponse некорректный ответ от сервера
	ErrBadResponse = errors.New("Invalid server response")
)
