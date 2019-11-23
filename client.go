package comarch

import (
	"bytes"
	"encoding/json"
	"github.com/sirupsen/logrus"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"
)

type accessToken struct {
	Token     string `json:"access_token"`
	Type      string `json:"token_type"`
	ExpiresIn int64  `json:"expires_in"`
}

type AccessToken struct {
	Value     string            `json:"value"`
	ExpiresAt time.Time         `json:"expires_at"`
	Cookies   map[string]string `json:"cookies"`
}

type GrantType string

const (
	GrantTypeByCard         GrantType = "authbycard"
	GrantTypeByPhone        GrantType = "authbyphone"
	GrantTypeBySMS          GrantType = "authbysms"
	GrantTypeCardActivation GrantType = "cardactivation"
)

type Client struct {
	basePath   string
	username   string
	password   string
	httpClient *http.Client
	log        *logrus.Logger
}

func New(log *logrus.Logger, basePath, login, password string, httpClient *http.Client) (*Client, error) {
	if strings.HasSuffix(basePath, "/") {
		return nil, ErrInvalidConfiguration
	}

	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	return &Client{
		basePath:   basePath,
		username:   login,
		password:   password,
		httpClient: httpClient,
		log:        log,
	}, nil
}

func (c *Client) makeAuthHeader(accessToken AccessToken) string {
	return "Bearer " + accessToken.Value
}

func (c *Client) SignInByCard(cardNo string, password string) (*AccessToken, error) {
	params := url.Values{}
	params.Set("grant_type", string(GrantTypeByCard))
	params.Set("cardNo", cardNo)
	params.Set("password", password)

	u := c.basePath + "/cwaapiinterface/login?" + params.Encode()

	req, err := http.NewRequest("POST", u, nil)
	if err != nil {
		return nil, err
	}

	req.SetBasicAuth(c.username, c.password)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, ErrBadResponse
	}

	publicToken, err := parseAccessToken(resp)
	if err != nil {
		return nil, err
	}

	reqDump, _ := httputil.DumpRequest(resp.Request, false)
	respDump, _ := httputil.DumpResponse(resp, false)
	c.log.WithFields(logrus.Fields{
		"req":      string(reqDump),
		"req_body": "",
		"resp":     string(respDump),
	}).Debug("Comarch req-resp")

	return publicToken, nil
}

func (c *Client) SignInByPhone(phoneNo string, password string) (*AccessToken, error) {
	params := url.Values{}
	params.Set("grant_type", string(GrantTypeByPhone))
	params.Set("phoneNo", phoneNo)
	params.Set("password", password)

	u := c.basePath + "/cwaapiinterface/login?" + params.Encode()

	req, err := http.NewRequest("POST", u, nil)
	if err != nil {
		return nil, err
	}

	req.SetBasicAuth(c.username, c.password)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, ErrBadResponse
	}

	publicToken, err := parseAccessToken(resp)
	if err != nil {
		return nil, err
	}

	return publicToken, nil
}

// SignInByPhoneOnly аутентификация пользователя по номеру телефона без пароля
func (c *Client) SignInByPhoneOnly(phoneNo string) (*AccessToken, error) {
	params := url.Values{}
	params.Set("grant_type", string(GrantTypeBySMS))
	params.Set("phoneNo", phoneNo)

	u := c.basePath + "/cwaapiinterface/login?" + params.Encode()

	req, err := http.NewRequest("POST", u, nil)
	if err != nil {
		return nil, err
	}

	req.SetBasicAuth(c.username, c.password)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, ErrBadResponse
	}

	publicToken, err := parseAccessToken(resp)
	if err != nil {
		return nil, err
	}

	return publicToken, nil
}

// SignInByCardNoOnly аутентификация пользователя по номеру карты без пароля
func (c *Client) SignInByCardNoOnly(cardNo string) (*AccessToken, error) {
	params := url.Values{}
	params.Set("grant_type", string(GrantTypeBySMS))
	params.Set("cardNo", cardNo)

	u := c.basePath + "/cwaapiinterface/login?" + params.Encode()

	req, err := http.NewRequest("POST", u, nil)
	if err != nil {
		return nil, err
	}

	req.SetBasicAuth(c.username, c.password)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, ErrBadResponse
	}

	publicToken, err := parseAccessToken(resp)
	if err != nil {
		return nil, err
	}

	return publicToken, nil
}

// ActivateCardNo активирует номер карты в комархе
func (c *Client) ActivateCardNo(cardNo string) (*AccessToken, error) {
	params := url.Values{}
	params.Set("grant_type", string(GrantTypeCardActivation))
	params.Set("cardNo", cardNo)

	u := c.basePath + "/cwaapiinterface/login?" + params.Encode()

	req, err := http.NewRequest("POST", u, nil)
	if err != nil {
		return nil, err
	}

	req.SetBasicAuth(c.username, c.password)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, ErrBadResponse
	}

	publicToken, err := parseAccessToken(resp)
	if err != nil {
		return nil, err
	}

	return publicToken, nil
}

// ResetPasswordByCardNo сбрасывает пароль дла данного номера карты на дефолтный в комархе
func (c *Client) ResetPasswordByCardNo(cardNo string) error {
	u := c.basePath + "/cwaapiinterface/common/passresetting"
	reqBytes, err := json.Marshal(map[string]string{"cardNo": cardNo})
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", u, bytes.NewBuffer(reqBytes))
	if err != nil {
		return err
	}

	req.SetBasicAuth(c.username, c.password)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return ErrBadResponse
	}

	return nil
}

// ResetPasswordByPhoneNo сбрасывает пароль дла данного номера телефона на дефолтный в комархе
func (c *Client) ResetPasswordByPhoneNo(phoneNo string) error {
	u := c.basePath + "/cwaapiinterface/common/passresetting"
	reqBytes, err := json.Marshal(map[string]string{"phoneNo": phoneNo})
	if err != nil {
		return err
	}

	req, err := http.NewRequest("POST", u, bytes.NewBuffer(reqBytes))
	if err != nil {
		return err
	}

	req.SetBasicAuth(c.username, c.password)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return ErrBadResponse
	}

	return nil
}

// формат даты, с которым работает комарх
const DATETIME_FMT = "2006-01-02 15:04"

type BalanceInfoResp struct {
	// номер карты
	CardNo string `json:"cardNo"`
	// последнее посещение
	// TODO: конвертация в DATETIME_FMT
	LastAuth      string          `json:"lastAuth"`
	BalanceInfo   BalanceInfo     `json:"balanceInfo"`
	ExpressPoints []ExpressPoints `json:"expressPoints"`
}

type BalanceInfo struct {
	// баланс баллов
	Balance int `json:"balance"`
	// идентификатор баланса. Использвоается в случае нескольких балансов
	BalanceID int `json:"balanceID"`
	// коэффициент пересчета. курс баллов по отношению к рублю
	BalanceRate int `json:"balanceRate"`
}

type ExpressPoints struct {
	// кол-во баллов
	Points int `json:"points"`
	// дата начисления
	// TODO: DATETIME_FMT
	IssueDate string `json:"issueDate"`
	// дата сгорания
	// TODO: DATETIME_FMT
	ExpiryDate string `json:"expiryDate"`
}

// GetBalanceInfo получает данные о состоянии баланса
func (c *Client) GetBalanceInfo(accessToken AccessToken) (*BalanceInfoResp, error) {
	u := c.basePath + "/cwaapiinterface/resources/balanceinfo"

	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Add("Authorization", c.makeAuthHeader(accessToken))
	for cookieName, cookieValue := range accessToken.Cookies {
		req.AddCookie(&http.Cookie{Name: cookieName, Value: cookieValue})
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, ErrBadResponse
	}

	var balanceInfoResp BalanceInfoResp
	if err := json.NewDecoder(resp.Body).Decode(&balanceInfoResp); err != nil {
		return nil, err
	}

	return &balanceInfoResp, nil
}

// ChangePassword изменяет пароля пользователя со старого на новый. текущий пароль не обязателен для установки нового.
func (c *Client) ChangePassword(accessToken AccessToken, password string, newPassword string) error {

	u := c.basePath + "/cwaapiinterface/resources/cards/password"

	reqBytes, err := json.Marshal(map[string]string{
		"oldPass": password,
		"newPass": newPassword,
	})
	if err != nil {
		return err
	}

	req, err := http.NewRequest("PUT", u, bytes.NewBuffer(reqBytes))
	if err != nil {
		return err
	}

	req.Header.Add("Authorization", c.makeAuthHeader(accessToken))
	for cookieName, cookieValue := range accessToken.Cookies {
		req.AddCookie(&http.Cookie{Name: cookieName, Value: cookieValue})
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return ErrBadResponse
	}

	return nil
}

type MartialStatus string

const (
	// MartialStatusMaried Женат
	MartialStatusMaried MartialStatus = "MARIED"
	// MartialStatusMarried Замужем
	MartialStatusMarried MartialStatus = "MARRIED"
	// MartialStatusUnmaried Неженат
	MartialStatusUnmaried MartialStatus = "UNMARIED"
	// MartialStatusUnmarried Незамужем
	MartialStatusUnmarried MartialStatus = "UNMARRIED"
)

type FavCategory string

const (
	// Бакалея и горячие напитки (чай, кофе)
	FavCategory1 FavCategory = "73:X_FD_Бакалея"
	// Вина, ликеры и крепкий алкоголь
	FavCategory2 FavCategory = "73:X_FD_Alcohol"
	// Все для дома, дачи, спорта
	FavCategory3 FavCategory = "73:X_FD_соп.тор"
	// Готовая кулинария и замороженные полуфабрикаты
	FavCategory4 FavCategory = "73:X_FD_Got.kulin.salat"
	// Диабетическое и Здоровое питание
	FavCategory5 FavCategory = "73:X_FD_Диаб.пит"
	// Молочная гастрономия
	FavCategory6 FavCategory = "73:X_FD_Мол.гас"
	// Мясо и птица
	FavCategory7 FavCategory = "73:X_FD_мяс.изд"
	// Овощи и фрукты
	FavCategory8 FavCategory = "73:X_FD_Ов.фр"
	// Рыба и морепродукты
	FavCategory9 FavCategory = "73:X_FD_Рыб.гас"
	// Соки, воды и слабоалкогольные напитки
	FavCategory10 FavCategory = "73:X_FD_Со.во.пи"
	// Сыры, колбасы, мясная гастрономия
	FavCategory11 FavCategory = "73:X_FD_Mias.gastranom"
	// Товары и продукты для детей
	FavCategory12 FavCategory = "73:X_FD_Тов.дет"
	// Хлеб и кондитерские изделия
	FavCategory13 FavCategory = "73:X_FD_Хл.бу.из."
)

type PersonalData struct {
	// Имя
	Name string `json:"name"`
	// Фамилия
	Surname string `json:"surname"`
	// Улица
	Street string `json:"street"`
	// Корпус
	HomeFraction string `json:"homeFraction"`
	// Дом
	Building string `json:"building"`
	// Квартира
	Flat string `json:"flat"`
	// Почтовый индекс
	PostCode string `json:"postCode"`
	// Город
	City string `json:"city"`
	// День рождения
	Birthday string `json:"birthday"`
	// Телефон
	Phone string `json:"phone"`
	// Доп.телефон
	SecondPhone string `json:"secondPhone"`
	// Моб. телефон
	MobilePhone string `json:"mobilePhone"`
	// Адрес эл.почты
	Mail string `json:"mail"`
	// Семейный статус, словарь CRH_FAMILY_STATUS
	// FIXME: WTF это словарь?
	// FIXME: use MartialStatus
	//MaritalStatus Dictionary `json:"maritalStatus"`
	// К-во детей
	Children int `json:"children"`
	// Допустимы контакты через по- чту: true– даfalse– нет
	PostNotification bool `json:"postNotification"`
	// Допустимы контакты через опе- ратора Горячей Линии: true– даfalse– нет
	PhoneNotification bool `json:"phoneNotification"`
	// Допустимы контакты черезe- mail: true– даfalse– нет
	MailNotification bool `json:"mailNotification"`
	// Согласие на получение рекла- мы: true– даfalse– нет
	SmsAdv bool `json:"smsAdv"`
	// Согласие на получение SMS: true– даfalse– нет
	SmslNotification bool `json:"smslNotification"`
	// Дата изменения любимых про- дуктов. Формат: ГГГГ-ММ-ДД
	FavPrdChangeDate string `json:"favPrdChangeDate"`
	// Сегмент любимых продуктов,словарь PRD_SGM_FAVORITE
	// FIXME: WTF это словарь?
	// FIXME: use FavCategory
	//FavPrdSegment Dictionary `json:"favPrdSegment"`
	// Согласие на обработку и ис- пользование персональных данных: true– даfalse– нет
	AcceptAdv bool `json:"acceptAdv"`
	// Пол
	Sex string `json:"sex"`
	// Согласие получать Push сооб- щения
	PushNotification bool `json:"pushNotification"`
	// Признак “Золотая карта”
	Golden bool `json:"golden"`
}

// CreateCardHolder создает новую учетную запись. Для доступа к данному методу необходим токен аутентификации клиента. Его можно получить, например, после активации номера карты.
// обязательными явлюятся след. поля name, surname, birthday, mobilePhone, acceptAdv.
func (c *Client) CreateCardHolder(accessToken AccessToken, personalData PersonalData) error {

	u := c.basePath + "/cwaapiinterface/resources/cardholders"

	reqBytes, err := json.Marshal(&personalData)
	if err != nil {
		return err
	}

	req, err := http.NewRequest("PUT", u, bytes.NewBuffer(reqBytes))
	if err != nil {
		return err
	}

	req.Header.Add("Authorization", c.makeAuthHeader(accessToken))
	for cookieName, cookieValue := range accessToken.Cookies {
		req.AddCookie(&http.Cookie{Name: cookieName, Value: cookieValue})
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return ErrBadResponse
	}

	return nil
}

// SignOut разлогин переданного токена
func (c *Client) SignOut(accessToken AccessToken) error {
	u := c.basePath + "/cwaapiinterface/logout"

	req, err := http.NewRequest("POST", u, nil)
	if err != nil {
		return err
	}

	req.Header.Add("Authorization", c.makeAuthHeader(accessToken))
	for cookieName, cookieValue := range accessToken.Cookies {
		req.AddCookie(&http.Cookie{Name: cookieName, Value: cookieValue})
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return ErrBadResponse
	}

	return nil
}

// TODO: не имплементирован метод смены пароля аутентифицированым пользователем. /common/passresetting
