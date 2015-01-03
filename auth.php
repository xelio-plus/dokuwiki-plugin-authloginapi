<?php

// must be run within Dokuwiki
if (!defined('DOKU_INC')) {
    die();
}

class auth_plugin_authloginapi extends DokuWiki_Auth_Plugin
{
    protected $token;

    /**
     * Constructor.
     */
    public function __construct()
    {
        parent::__construct();

        $this->cando['external'] = true;

        $this->token = $this->getConf('token');

        $this->success = true;
    }

    /**
     * Do all authentication
     *
     * @param  string $user   Username
     * @param  string $pass   Cleartext Password
     * @param  bool   $sticky Cookie should not expire
     * @return bool   true on successful auth
     */
    public function trustExternal($user, $pass, $sticky = false)
    {
        global $USERINFO;
        global $ACT;

        $session = $_SESSION[DOKU_COOKIE]['auth'];
        if (isset($session['info'])) {
            $_SERVER['REMOTE_USER'] = $session['user'];
            $USERINFO = $session['info'];

            return true;
        }

        if ($ACT == 'login' && isset($_GET['r']) && isset($_GET['s'])) { // parse response
            $data = $this->parseResponse($_GET['r'], $_GET['s']);

            if (!$data || $data['action'] != 'login' || !isset($data['success']) || !$data['success']) {
                msg($this->getLang('login_failed'), -1);

                return false;
            }
            if (!isset($data['user']['groups'])) {
                $data['user']['groups'] = array();
            }

            $this->setUserSession($data['user']['id'], $data['user']['username'], $data['user']['groups']);

            return true;
        }

        return false;
    }

    /**
     * Parse and validate a backend response
     *
     * @param  string     $raw
     * @param  string     $signature
     * @return array|null
     */
    protected function parseResponse($raw, $signature)
    {
        $signatureInput = $raw.$this->token;
        $signatureExpected = hash('sha256', $signatureInput);
        if ($signatureExpected != $signature) {
            return;
        }

        $data = json_decode(base64_decode(str_pad(strtr($raw, '-_', '+/'), strlen($raw) % 4, '=', STR_PAD_RIGHT)), true);
        if (!$data || !isset($data['time']) || !isset($data['action'])) {
            return;
        }

        if (abs($data['time'] - time()) > 600) {
            return;
        }

        return $data;
    }

    /**
     * Setup session to login a user
     *
     * @param string $id
     * @param string $username
     * @param array  $groups
     */
    protected function setUserSession($id, $username, $groups = array())
    {
        global $USERINFO;

        $groups = array_unique($groups);

        $USERINFO['name'] = $username;
        $USERINFO['mail'] = '';
        $USERINFO['grps'] = $groups;
        $_SERVER['REMOTE_USER'] = $id;

        $_SESSION[DOKU_COOKIE]['auth']['user'] = $id;
        $_SESSION[DOKU_COOKIE]['auth']['info'] = $USERINFO;
    }
}
