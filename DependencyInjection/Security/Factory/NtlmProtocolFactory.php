<?php
namespace BrowserCreative\NtlmBundle\DependencyInjection\Security\Factory;

use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;
use Symfony\Component\DependencyInjection\DefinitionDecorator;
use Symfony\Component\Config\Definition\Builder\NodeDefinition;
use Symfony\Bundle\SecurityBundle\DependencyInjection\Security\Factory\SecurityFactoryInterface;

class NtlmProtocolFactory implements SecurityFactoryInterface
{
    public function create(ContainerBuilder $container, $id, $config, $userProvider, $defaultEntryPoint)
    {
        // provider
        $providerId = 'ntlm.security.authentication.provider.ntlm_flexy.'.$id;
        $container
            ->setDefinition($providerId, new DefinitionDecorator('ntlm.security.authentication.provider.ntlm_flexy'))
            ->replaceArgument(0, new Reference($userProvider))
            ->replaceArgument(1, new Reference($config['token_validator']))
            ->replaceArgument(2, $id)
        ;

        // entry point
        if (null === $defaultEntryPoint) {
            $entryPointId = 'ntlm.security.authentication.ntlm_entry_point.' . $id;
            $container
                ->setDefinition($entryPointId,
                    new DefinitionDecorator('ntlm.security.authentication.ntlm_entry_point'))
                ->replaceArgument(1, $config['target'])
                ->replaceArgument(2, $config['server'])
                ->replaceArgument(3, $config['domain'])
                ->replaceArgument(4, $config['dns_server'])
                ->replaceArgument(5, $config['dns_domain'])
                ->replaceArgument(6, $config['ntlm_addresses'])
                ->replaceArgument(7, $config['redirect_to_login_form_on_failure'])
            ;
            $defaultEntryPoint = $entryPointId;
        }

        // listener
        $listenerId = 'ntlm.security.authentication.listener.ntlmprotocol.' . $id;
        $container->setDefinition($listenerId,
            new DefinitionDecorator('ntlm.security.authentication.listener.ntlmprotocol'))
            ->replaceArgument(1, new Reference($defaultEntryPoint))
            ->replaceArgument(2, new Reference($providerId))
            ->replaceArgument(3, $id)
            ;

        // If the application does logout, add our handler to allow to log the user out of other apps, too
        if ($container->hasDefinition('security.logout_listener.'.$id)) {
            $logoutListener = $container->getDefinition('security.logout_listener.'.$id);
            $addHandlerArguments = array(new Reference('ntlm.security.http.logout.' . $id));

            // Don't add the handler again if it has already been added by another factory
            if (!in_array(array('addHandler', $addHandlerArguments),
                    $logoutListener->getMethodCalls())) {

                $container->setDefinition('ntlm.security.http.logout.' . $id,
                            new DefinitionDecorator('ntlm.security.http.logout'));
                $logoutListener->addMethodCall('addHandler', $addHandlerArguments);
            }
        }

        return array($providerId, $listenerId, $defaultEntryPoint);
    }

    /// @todo verify: is this position correct, or shall it be moved to 'http' ?
    public function getPosition()
    {
        return 'remember_me';
    }

    public function getKey()
    {
        return 'ntlm-protocol';
    }

    public function addConfiguration(NodeDefinition $node)
    {
        $node
            ->children()
                ->scalarNode('target')->end()
                ->scalarNode('server')->end()
                ->scalarNode('domain')->end()
                ->scalarNode('dns_server')->end()
                ->scalarNode('dns_domain')->end()
                ->booleanNode('redirect_to_login_form_on_failure')->defaultValue(true)->end()
                ->arrayNode('ntlm_addresses')
                    ->useAttributeAsKey('key')
                    ->prototype('scalar')->end()
                ->end()
                ->scalarNode('token_validator')->end()
            ->end()
        ;
    }
}