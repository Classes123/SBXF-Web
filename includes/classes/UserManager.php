<?php
class UserManager {
  private static $instance = NULL;
  private static $aid = -1;

  public static function init($aid, $hash = '') {
    if (self::$instance !== NULL)
      return;

    if (is_int($aid))
      self::$aid = $aid;

    self::$instance = new CUserManager(self::$aid, $hash);
    self::$aid = self::$instance->aid;

    if (self::$aid != -1) {
      self::updateEntity('lastvisit', time()); // update visiting time
    }
  }

  public static function getInstance() {
    if (self::$instance === NULL)
      self::init(-1);

    return self::$instance;
  }

  public static function login($username, $password, &$reason) {
    if (empty($password)) {
      $reason = 'Не указан пароль.';
      return false;
    }

    $reason = 'Неверный логин и/или пароль';

    $at = isset($GLOBALS['config']['auth.type']) ? $GLOBALS['config']['auth.type'] : 0;

    $is_xenforo = ($at == 3 || $at == 4);

    //XenForo auth
    if ($is_xenforo)
    {
        if (!defined('XF_API_URL') || !defined('XF_API_KEY'))
        {
            $reason = 'Авторизация не настроена. Обратитесь к администратору.';
            return false;
        }

        $headers = [
            'Content-Type: application/x-www-form-urlencoded',
            'XF-Api-Key: ' . XF_API_KEY
        ];

        $curl_result = self::sendRequest(XF_API_URL . '/auth', 'post', $headers, [
                'login' => $username,
                'password' => $password,
        ]);

        $json = self::fetchJson($curl_result, $reason);
        if (!$json)
        {
            return false;
        }

        if (isset($json['errors']))
        {
            $code = $json['errors'][0]['code'];

            switch($code)
            {
                case 'incorrect_password':
                case 'requested_user_x_not_found':
                    break;
                case 'your_account_is_currently_security_locked':
                    $reason = 'Ваш аккаунт в данный момент был заблокирован по соображениям безопасности';
                    break;
                case 'your_account_has_temporarily_been_locked_due_to_failed_login_attempts':
                    $reason = 'Ваш аккаунт был временно заблокирован из-за неверных попыток ввода пароля';
                    break;
                default:
                    $reason = 'Обратитесь к администратору. (' . $code . ')';
                    break;
            }

            return false;
        }

        $curl_result = self::sendRequest(
            XF_API_URL . '/eapi/users/' . $json['user']['user_id'] . '/connected-accounts',
            'get',
            $headers,
            []
        );

        $json = self::fetchJson($curl_result, $reason);
        if (!$json)
        {
            return false;
        }

        if (isset($json['errors']))
        {
            $reason = 'Обратитесь к администратору. (' . $json['errors'][0]['code'] . ')';
            return false;
        }

        if (!isset($json['steam']))
        {
            return false;
        }

        $steamId = \CSteamId::factory($json['steam'])->v2;

        $DB = \DatabaseManager::GetConnection();
        $DB->Prepare('SELECT `aid`, `password`, `expired` FROM `{{prefix}}admins` WHERE `authid` LIKE :pattern');
        $DB->BindData('pattern', '%' . str_replace('STEAM_0:', '', $steamId));
    }
    else
    {
        $DB = \DatabaseManager::GetConnection();
        $DB->Prepare('SELECT `aid`, `password`, `expired` FROM `{{prefix}}admins` WHERE `user` = :username');
        $DB->BindData('username', $username);
    }

    $Result = $DB->Finish();

    $Data = $Result->Single();
    $Result->EndData();

    if (!$Data)
    {
        return false;
    }

    if ($is_xenforo)
    {
        return self::ContinueLogin($Data, $reason);
    }

    if (empty($Data['password']))
    {
        $reason = 'У пользователя не задан пароль. Обратитесь к администратору.';
        return false;
    }

    // try use new algo.
    if (password_verify($password, $Data['password']))
      return self::ContinueLogin($Data, $reason);

    // using old algo.
    if ($Data['password'] == sha1(sha1('SourceBans' . $password))) {
      // rehash user with new algo.
      $Data['password'] = password_hash($password, PASSWORD_DEFAULT);
      $DB->Prepare('UPDATE `{{prefix}}admins` SET `password` = :password WHERE `aid` = :id');
      $DB->BindMultipleData([
        'password'  => $Data['password'],
        'id'        => $Data['aid']
      ]);
      $DB->Finish();

      // and continue login logic.
      return self::ContinueLogin($Data, $reason);
    }
    return false;
  }

  public static function forceLoginBySteam($steamId, &$reason) {
    if (!is_object($steamId) || get_class($steamId) != 'CSteamId')
      throw new \LogicException('Invalid SteamID object passed.');

    $DB = \DatabaseManager::GetConnection();
    $DB->Prepare('SELECT `aid`, `password`, `expired` FROM `{{prefix}}admins` WHERE `authid` LIKE :auth');
    $DB->BindData('auth', '%' . str_replace('STEAM_0:', '', $steamId->v2));

    $Result = $DB->Finish();
    $UserData = $Result->Single();
    $Result->EndData();

    if (!$UserData) {
      $reason = 'Пользователя с Вашим SteamID не найдено.';
      return false;
    }

    return self::ContinueLogin($UserData, $reason);
  }

  public static function getMyID() {
    return self::$aid;
  }

  private static function ContinueLogin($UserData, &$reason) {
    if ($UserData['expired'] != 0 && $UserData['expired'] < time()) {
      $reason = 'Ваши привилегии истекли. Их необходимо продлить для дальнейшего использования.';
      return false;
    }

    $_SESSION['admin_id'] = intval($UserData['aid']);
    $_SESSION['admin_hash'] = $UserData['password'];
    \session_write_close();
    return true;
  }

  private static function updateEntity($field, $value) {
    $DB = \DatabaseManager::GetConnection();
    $DB->Prepare("UPDATE `{{prefix}}admins` SET $field = :value WHERE `aid` = :id");
    $DB->BindData('id', self::$aid);
    $DB->BindData('value', $value);
    $DB->Finish();
  }

  private static function sendRequest($url, $method, $headers, $params)
  {
      $curl = curl_init($url);

      if ($method == 'post')
      {
          curl_setopt($curl, CURLOPT_POST, true);
          curl_setopt($curl, CURLOPT_POSTFIELDS, http_build_query($params));
      }

      curl_setopt($curl, CURLOPT_HTTPHEADER, $headers);
      curl_setopt($curl, CURLOPT_RETURNTRANSFER, true);

      $curl_result = curl_exec($curl);

      curl_close($curl);

      return $curl_result;
  }

  private static function fetchJson($response, &$reason)
  {
      static $inc;

      $inc++;

      if (!$response)
      {
          $reason = 'Не удалось получить ответ от сервера (' . $inc . '). Обратитесь к администратору';
          return false;
      }

      $json = json_decode($response, true);
      if ($json === false)
      {
          $reason = 'Не удалось распознать ответ от сервера (' . $inc . '). Обратитесь к администратору';
          return false;
      }

      return $json;
  }
}