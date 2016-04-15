class User < ActiveRecord::Base
  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable and :omniauthable
  after_save :send_welcome_email
  
  mount_uploader :avatar, AvatarUploader
  attr_accessor :login
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :trackable, :validatable,  :confirmable, :omniauthable


  validates :username, presence: true, length: {maximum: 255}, uniqueness: { case_sensitive: false }, format: { with: /\A[a-zA-Z0-9]*\z/, message: "may only contain letters and numbers." }
 
   def self.find_first_by_auth_conditions(warden_conditions)
     conditions = warden_conditions.dup
     if login = conditions.delete(:login)
       where(conditions).where(["username = :value OR lower(email) = lower(:value)", { :value => login }]).first
     else
       where(conditions).first
     end
   end

   def send_welcome_email
    if self.confirmed_at_changed? && confirmed_at_was.nil?
    UserMailer.welcome_email(self).deliver_later
  end
  end
end

