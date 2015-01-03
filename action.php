<?php

// must be run within Dokuwiki
if (!defined('DOKU_INC')) {
    die();
}

class action_plugin_authloginapi extends DokuWiki_Action_Plugin
{
    protected $active;
    protected $endpoint;
    protected $token;

    /**
     * Constructor
     */
    public function __construct()
    {
        global $conf;

        $this->active = (
            $conf['authtype'] == 'authloginapi' ||
            (
                $conf['authtype'] == 'authsplit' &&
                $conf['plugin']['authsplit']['primary_authplugin'] == 'authloginapi'
            )
        );

        $this->endpoint = $this->getConf('endpoint');
        $this->token = $this->getConf('token');
    }
    /**
     * {@inheritDoc}
     */
    public function register(Doku_Event_Handler &$controller)
    {
        $controller->register_hook('HTML_LOGINFORM_OUTPUT', 'BEFORE', $this, 'handle_login_form');
    }

    /**
     * Modify login form to send a request to Login API Server
     *
     * @param Doku_Event $event
     * @param object     $param
     */
    public function handle_login_form(Doku_Event &$event, $param)
    {
        global $ID;

        if (!$this->active) {
            return;
        }

        $form = $event->data;
        $removedFields = array('textfield', 'passwordfield', 'checkboxfield');
        foreach ($removedFields as $fieldType) {
            while (($field = $form->findElementByType($fieldType)) !== false) {
                $form->replaceElement($field, null);
            }
        }
        $buttonPos = $form->findElementByType('button');
        $button = $form->getElementAt($buttonPos);
        $button['value'] = $this->getConf('button');
        $form->replaceElement($buttonPos, $button);

        $request = array(
            'time' => time(),
            'return' => $this->buildReturnUrl(array('do' => 'login')),
            'action' => 'login',
            'site' => $this->getSiteName(),
        );

        $encoded = rtrim(strtr(base64_encode(json_encode($request)), '+/', '-_'), '=');
        $form->addHidden('r', $encoded);

        $signature = hash('sha256', $encoded.$this->token);
        $form->addHidden('s', $signature);

        $form->params['action'] = $this->endpoint;
        $form->params['method'] = 'get';
    }

    /**
     * Build a URL which will be the redirection target after login
     *
     * @param  array  $params Additional parameters (appended to query)
     * @return string
     */
    protected function buildReturnUrl($params = array())
    {
        global $ID;

        return wl($ID, $params, true, '&');
    }

    /**
     * Return the wiki name
     *
     * @return string
     */
    protected function getSiteName()
    {
        global $conf;

        return $conf['title'];
    }
}
