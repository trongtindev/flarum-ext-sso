<?php

namespace Maicol07\SSO;

use DateTimeZone;
use Exception;
use Flarum\Bus\Dispatcher;
use Flarum\Http\RememberAccessToken;
use Flarum\Http\SessionAccessToken;
use Flarum\Settings\SettingsRepositoryInterface;
use Flarum\User\Command\RegisterUser;
use Flarum\User\Exception\PermissionDeniedException;
use Flarum\User\User;
use Flarum\User\UserRepository;
use Illuminate\Database\Eloquent\ModelNotFoundException;
use Illuminate\Support\Arr;
use Illuminate\Support\Str;
use InvalidArgumentException;
use Laminas\Diactoros\Response\JsonResponse;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface as Request;
use Psr\Http\Server\RequestHandlerInterface;
use Firebase\JWT\JWT;
use Firebase\JWT\Key;

class JWTSSOController implements RequestHandlerInterface
{
   /** @var UserRepository */
   private $users;

   /** @var Dispatcher */
   private $bus;

   /** @var string */
   private $site_url;

   /** @var string */
   private $iss;

   /** @var string */
   private $signing_algorithm;

   /** @var string */
   private $signer_key;

   /**
    * @param Dispatcher $bus
    * @param UserRepository $users
    * @param SettingsRepositoryInterface $settings
    */
   public function __construct(
      Dispatcher                  $bus,
      UserRepository              $users,
      SettingsRepositoryInterface $settings
   ) {
      $this->bus = $bus;
      $this->users = $users;
      $this->site_url = resolve('flarum.config')['url'];
      $this->iss = $settings->get('maicol07-sso.jwt_iss');
      $this->signing_algorithm = $settings->get('maicol07-sso.jwt_signing_algorithm') ?? 'Sha256';
      $this->signer_key = $settings->get('maicol07-sso.jwt_signer_key');
   }

   /**
    * @param Request $request
    * @return ResponseInterface
    *
    * @throws PermissionDeniedException
    *
    * @noinspection RegExpRedundantEscape
    */
   final public function handle(Request $request): ResponseInterface
   {
      // Get token
      $access_token = $_GET['access_token'] ?? '';
      if (empty($access_token)) {
         http_response_code(400);
         throw new InvalidArgumentException("No Authorization header was set");
      }

      $header = preg_grep('/^[A-Za-z0-9\-_\=]+\.[A-Za-z0-9\-_\=]+\.?[A-Za-z0-9\-_.+\/\=]*$/', explode(', ', $access_token));
      if (empty($header)) {
         http_response_code(400);
         throw new InvalidArgumentException("No JWT found in Authorization headers");
      }

      // Decode JWT
      $decoded = JWT::decode($access_token, new Key($this->signer_key, 'HS256'));
      if (!isset($decoded->exp) || !isset($decoded->iss)) {
         throw new PermissionDeniedException('Signature key does not correspond to the one on the token!');
      }

      if (!isset($decoded->attributes) || !isset($decoded->attributes->avatarUrl)) {
         throw new Exception('Missing attributes in JWT payload! {uid, attributes.username, attributes.avatarUrl, attributes.isEmailConfirmed}');
      }

      // remove any sizing params
      $avatar = $decoded->attributes->avatarUrl;
      $param = '?sz=';
      if (strpos($avatar, $param)) {
         $avatar = substr($avatar, 0, strpos($avatar, $param));
      }

      try {
         $user = $this->users->findOrFail($decoded->uid);
      } catch (ModelNotFoundException $e) {
         $email = $decoded->attributes->email;
         $username = $decoded->attributes->username;
         $user = $this->users->findByIdentification($email ?? $username);
      }

      if ($user === null) {
         $actor = $this->users->findOrFail(1);
         $attributes = [
            'email' => $decoded->attributes->email,
            'username' => $decoded->attributes->username,
            'password' => md5(rand(11111, 9999) . $decoded->uid),
            'avatarUrl' => $decoded->attributes->avatarUrl,
            'isEmailConfirmed' => $decoded->attributes->isEmailConfirmed,
         ];

         // User is already activated since the isEmailConfirmed attribute has been set to true
         $user = $this->bus->dispatch(new RegisterUser($actor, ['attributes' => $attributes]));
         assert($user instanceof User);
      }

      $user->changeAvatarPath($avatar);
      $user->save();

      $token = $this->getToken($user, true);

      return new JsonResponse([
         'token' => $token,
         'userId' => $user->id
      ]);
   }

   private function getToken(User $user, bool $remember = false): string
   {
      /** @noinspection PhpUnhandledExceptionInspection */
      $token = $remember ? RememberAccessToken::generate($user->id) : SessionAccessToken::generate($user->id);
      $token->save();

      return $token->token;
   }
}
