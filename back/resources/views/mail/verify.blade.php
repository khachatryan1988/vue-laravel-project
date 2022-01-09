<h2> Hey there  <b><i>{{$user->name}}</i></b></h2>
<h4> We are thrilled for you to join our Team!!!</h4>
<p> Please verify your email with this link
    <button><a href="{{ env('APP_FRONT_URL')."$user->email"."&token=$token"}}">Link</a></button>
</p>
