<?php

namespace BrowserCreative\NtlmBundle\Security\Authentication\Token;

use Symfony\Component\Security\Core\Authentication\Token\AbstractToken;

/**
 * @todo save in token the whole challenge data as well
 */
class NtlmToken extends AbstractToken
{
    private $providerKey;

    /**
     * Constructor.
     *
     * @param string|object            $user        The username (like a nickname, email address, etc.), or a UserInterface instance or an object implementing a __toString method.
     * @param array                    $ntlmInfo
     * @param string                   $providerKey The provider key
     * @param RoleInterface[]|string[] $roles       An array of roles
     *
     * @throws \InvalidArgumentException
     */
    public function __construct($user, $ntlmInfo, $providerKey, array $roles = array())
    {
        parent::__construct($roles);

        if (empty($providerKey)) {
            throw new \InvalidArgumentException('$providerKey must not be empty.');
        }

        $this->setUser($user);
        $this->setAttributes($ntlmInfo);
        $this->providerKey = $providerKey;

        parent::setAuthenticated(count($roles) > 0);
    }

    /**
     * {@inheritdoc}
     */
    public function setAuthenticated($isAuthenticated)
    {
        if ($isAuthenticated && !$this->isAuthenticated()) {
            throw new \LogicException('Cannot set this token to trusted after instantiation.');
        }

        parent::setAuthenticated(false);
    }

    /**
     * @todo
     */
    public function getCredentials()
    {
        //return $this->credentials;
        return null;
    }

    /**
     * Returns the provider key.
     *
     * @return string The provider key
     */
    public function getProviderKey()
    {
        return $this->providerKey;
    }

    /**
     * {@inheritdoc}
     */
    /*public function eraseCredentials()
    {
        parent::eraseCredentials();

        $this->credentials = null;
    }*/

    /**
     * {@inheritdoc}
     */
    public function serialize()
    {
        return serialize(array($this->providerKey, parent::serialize()));
    }

    /**
     * {@inheritdoc}
     */
    public function unserialize($serialized)
    {
        list($this->providerKey, $parentStr) = unserialize($serialized);
        parent::unserialize($parentStr);
    }
}