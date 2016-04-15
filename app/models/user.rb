class User < ActiveRecord::Base
  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable and :omniauthable
  after_save :send_welcome_email
  
  mount_uploader :avatar, AvatarUploader
  attr_accessor :login
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :trackable, :validatable,  :confirmable, :omniauthable

  
   def self.find_first_by_auth_conditions(warden_conditions)
     conditions = warden_conditions.dup
     if login = conditions.delete(:login)
       where(conditions).where(["username = :value OR lower(email) = lower(:value)", { :value => login }]).first
     else
       where(conditions).first
     end
   end

   def self.from_omniauth(auth)
  where(provider: auth.provider, uid: auth.uid).first_or_create do |user|
    user.email = auth.info.email
    user.password = Devise.friendly_token[0,20]
    user.name = auth.info.name   # assuming the user model has a name
    user.avatar = auth.info.image # assuming the user model has an image
    user.skip_confirmation!
  end
end

  def self.new_with_session(params, session)
    super.tap do |user|
      if data = session["devise.facebook_data"] && session["devise.facebook_data"]["extra"]["raw_info"]
        user.email = data["email"] if user.email.blank?
        user.valid?
      end
    end
  end

   def send_welcome_email
    if self.confirmed_at_changed? && confirmed_at_was.nil?
    UserMailer.welcome_email(self).deliver_later
  end
  end


end

